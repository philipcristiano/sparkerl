-module(sparkerl_spark_protocol_fsm).

-behaviour(gen_fsm).
-behaviour(ranch_protocol).
-compile([{parse_transform, lager_transform}]).

-include_lib("gen_coap/include/coap.hrl").

%% API
-export([start_link/4]).

%% gen_fsm callbacks
-export([init/1,
         init/4,
         state_name/3,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         terminate/3,
         code_change/4]).

-export([communicating/2,
         validate_nonce/2,
         validate_hello/2]).

-record(state, {socket,
                transport,
                recv_buffer= <<>>,
                private_key,
                nonce,
                outgoing_iv,
                incoming_iv,
                outgoing_id,
                aes_key,
                aes_salt}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Ref, Socket, Transport, Opts) ->
    proc_lib:start_link(?MODULE, init, [Ref, Socket, Transport, Opts]).


%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm is started using gen_fsm:start/[3,4] or
%% gen_fsm:start_link/[3,4], this function is called by the new
%% process to initialize.
%%
%% @spec init(Args) -> {ok, StateName, State} |
%%                     {ok, StateName, State, Timeout} |
%%                     ignore |
%%                     {stop, StopReason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    ok.

init(Ref, Socket, Transport, _Opts = []) ->
    ok = proc_lib:init_ack({ok, self()}),
    %% Perform any required state initialization here.
    ok = ranch:accept_ack(Ref),
    ok = Transport:setopts(Socket, [{active, once}]),
    PKF = application:get_env(sparkerl, private_key, "default-key.pem"),
    {ok, Pem} = file:read_file(PKF),
    [PemEntries] = public_key:pem_decode(Pem),
    PK = public_key:pem_entry_decode(PemEntries),
    lager:info("Received Connection"),

    Nonce = crypto:rand_bytes(40),
    Transport:send(Socket, Nonce),
    lager:info("Sending nonce: ~p", [Nonce]),

    State = #state{socket=Socket,
                   transport=Transport,
                   private_key=PK,
                   nonce=Nonce},

    gen_fsm:enter_loop(?MODULE, [], validate_nonce, State).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_event/2, the instance of this function with the same
%% name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%
%% @spec state_name(Event, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
validate_nonce({tcp, Data}, State=#state{private_key=PK, nonce=Nonce, socket=Socket, transport=Transport}) ->
    Plain = public_key:decrypt_private(Data, PK),

    <<Nonce:40/binary, ID:96, Rest/binary>> = Plain,
    lager:info("SMT ID: ~p", [ID]),

    ClientPemFile = erlang:integer_to_list(ID) ++ ".pub.pem",
    ClientPemPath = "keys/" ++ ClientPemFile,
    lager:debug("Trying to find pem file ~p~n", [ClientPemPath]),
    {ok, ClientPem} = file:read_file(ClientPemPath),
    [PemEntries] = public_key:pem_decode(ClientPem),
    ClientPubKey = public_key:pem_entry_decode(PemEntries),

    {NewState, Msg} = create_session_msg(PK, ClientPubKey, State),
    Transport:send(Socket, Msg),
    ok = Transport:setopts(Socket, [{active, once}]),

    {next_state, validate_hello, NewState};

validate_nonce(Event, State) ->
    lager:info("Unknown Event ~p", [Event]),
    {next_state, validate_nonce, State}.

create_session_msg(PrivKey, PubKey, State) ->
    % Server generates 40 bytes of secure random data to serve as components
    % of a session key for AES-128-CBC encryption. The first 16 bytes (MSB
    % first) will be the key, the next 16 bytes (MSB first) will be the
    % initialization vector (IV), and the final 8 bytes (MSB first) will be
    % the salt. Server RSA encrypts this 40-byte message using the Core's
    % public key to create a 128-byte ciphertext.
    SessionKey = crypto:strong_rand_bytes(40),
    <<Key:16/binary, IV:16/binary, Salt:8/binary>> = SessionKey,
    <<CipherText:128/binary>> = public_key:encrypt_public(SessionKey, PubKey),
    NewState = State#state{outgoing_iv=IV,
                           incoming_iv=IV,
                           aes_key=Key,
                           aes_salt=Salt},
    % Server creates a 20-byte HMAC of the ciphertext using SHA1 and the 40
    % bytes generated in the previous step as the HMAC key.
    HMAC = crypto:hmac(sha, SessionKey, CipherText, 20),

    % Server signs the HMAC with its RSA private key generating a 256-byte
    % signature.
    SignedHMAC = public_key:encrypt_private(HMAC, PrivKey),

    % Server sends 384 bytes to Core: the ciphertext then the signature.
    {NewState, [CipherText, SignedHMAC]}.

validate_hello({tcp, Data}, State=#state{socket=Socket, transport=Transport}) ->
    lager:debug("Hello event ~p", [Data]),
    << Something:2/binary, CipherText:16/binary>> = Data,
    lager:debug("Hello ciphertext ~p", [CipherText]),
    {ok, PlainText, NewState} = decrypt_aes(CipherText, State),
    lager:debug("Hello plaintext ~p", [PlainText]),
    Hello = coap_message_parser:decode(PlainText),
    lager:info("Hello coap ~p", [Hello]),
    parse_hello_payload(Hello#coap_message.payload),

    lager:info("Responding with Hello"),
    {ok, NewState1} = send_hello_bin(NewState),

    {next_state, communicating, NewState1};

validate_hello(Event, State) ->
    lager:info("Unhandled Hello Event ~p", [Event]),
    {next_state, validate_hello, State}.

parse_hello_payload(<<ProductId:16, FirmwareVersion:16, Flags:8, NewlyUpgraded:8, PlatformId:16, Rest/binary>>) ->
    lager:info("ProductId ~p", [ProductId]),
    lager:info("FirmwareVersion ~p", [FirmwareVersion]),
    lager:info("Flags ~p", [Flags]),
    lager:info("NewlyUpgraded ~p", [NewlyUpgraded]),
    lager:info("PlatformId ~p", [PlatformId]),
    ok.

send_coap(Msg=#coap_message{id=undefined}, State=#state{outgoing_id=OutgoingId}) ->
    NewId = OutgoingId + 1,
    MsgWithId = Msg#coap_message{id=NewId},
    StateWithId = State#state{outgoing_id=OutgoingId},
    send_coap(MsgWithId, StateWithId);
send_coap(Msg=#coap_message{}, State=#state{}) ->
    lager:info("Making new message ~p", [Msg]),
    Bin = coap_message_parser:encode(Msg),
    {ok, SentState} = send(Bin, State),
    {ok, SentState}.

send(Data, State=#state{socket=Socket, transport=Transport}) ->
    {ok, OutgoingCipher, NewState} = encrypt_aes(Data, State),
    Size = erlang:byte_size(OutgoingCipher),
    Transport:send(Socket, [<< Size:16>>, OutgoingCipher]),
    ok = Transport:setopts(Socket, [{active, once}]),
    {ok, NewState}.

decrypt_aes(EncryptedBin, State=#state{aes_key=Key, incoming_iv=IV}) ->
    lager:debug("Decrypting ~p", [EncryptedBin]),
    lager:debug("Decrypting with IV ~p", [IV]),
    PlainBin = crypto:block_decrypt(aes_cbc256, Key, IV, EncryptedBin),
    NewState=State#state{incoming_iv=next_iv(EncryptedBin)},
    lager:debug("Next decrypt with IV ~p", [NewState#state.incoming_iv]),
    UnpaddedBin = pkcs7:unpad(PlainBin),
    {ok, UnpaddedBin, NewState}.

next_iv(<<First16Bytes:16/binary, _Rest/binary>>) ->
    First16Bytes.

encrypt_aes(PlainBin, State=#state{aes_key=Key, outgoing_iv=IV}) ->
    lager:debug("Encrypting ~p", [PlainBin]),
    PaddedBin = pkcs7:pad(PlainBin),
    lager:debug("padded to ~p", [PaddedBin]),

    EncryptedBin = crypto:block_encrypt(aes_cbc256, Key, IV, PaddedBin),
    NewState=State#state{outgoing_iv=crypto:next_iv(aes_cbc, EncryptedBin)},
    {ok, EncryptedBin, NewState}.

send_hello_bin(State) ->
    Id = random:uniform(65536),
    Padding = <<>>,
    StateWithId=State#state{outgoing_id=Id},
    Hello = #coap_message{type=non,
                          method='post',
                          payload=Padding,
                          options=[{uri_path,[<<"h">>]}]},
    lager:info("Outgoing Hello ~p", [Hello]),
    {ok, NewState} = send_coap(Hello, StateWithId),
    {ok, NewState}.


communicating({tcp, Data}, State) ->
    lager:debug("Have data of size ~p", [erlang:byte_size(Data)]),
    lager:debug("Processing Data ~p", [Data]),
    {ok, PlainText, NewState} = decrypt_aes(Data, State),
    lager:debug("Plain text: ~p", [PlainText]),
    Msg = coap_message_parser:decode(PlainText),
    lager:info("Received coap ~p", [Msg]),
    NewState2 = handle_coap(Msg, NewState),
    {next_state, communicating, NewState2};

communicating(Event, State) ->
    lager:info("Unhandled Communicating Event ~p", [Event]),
    {next_state, communicating, State}.

handle_coap(Msg=#coap_message{options=[{uri_path,[<<"t">>]}]}, State) ->
    lager:info("Client is asking for the time, ~p", [Msg]),
    State;

handle_coap(Msg=#coap_message{type=con, method=undefined}, State=#state{}) ->
    lager:info("Client is pinging, I should send one back! ~p", [Msg]),
    PingAck = #coap_message{type=ack, method=undefined},
    {ok, NewState} = send_coap(PingAck, State),
    NewState;

handle_coap(Msg, State) ->
    lager:info("Unhandled coap message ~p", [Msg]),
    State.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_event/[2,3], the instance of this function with
%% the same name as the current state name StateName is called to
%% handle the event.
%%
%% @spec state_name(Event, From, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
state_name(_Event, _From, State) ->
    Reply = ok,
    {reply, Reply, state_name, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event.
%%
%% @spec handle_event(Event, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/[2,3], this function is called
%% to handle the event.
%%
%% @spec handle_sync_event(Event, From, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    {reply, Reply, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it receives any
%% message other than a synchronous or asynchronous event
%% (or a system message).
%%
%% @spec handle_info(Info,StateName,State)->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_info({tcp, Port, IncommingData}, communicating, State=#state{recv_buffer=Buffer, transport=Transport, socket=Socket}) ->
    lager:debug("Received packet!"),
    ToProcess = <<Buffer/binary, IncommingData/binary>>,
    LeftoverBuffer = c_parse_chunk(ToProcess),
    lager:debug("Recv buffer size ~p", [byte_size(LeftoverBuffer)]),
    NewState = State#state{recv_buffer=LeftoverBuffer},
    ok = Transport:setopts(Socket, [{active, once}]),

    {next_state, communicating, NewState};

handle_info({tcp, Port, Data}, StateName, State) ->
    ok = gen_fsm:send_event(self(), {tcp, Data}),
    {next_state, StateName, State};

handle_info(Info, StateName, State) ->
    lager:info("Info ~p", [Info]),
    {next_state, StateName, State}.

c_parse_chunk(<<Size:16, Data:Size/binary, Rest/binary>>) ->
    ok = gen_fsm:send_event(self(), {tcp, Data}),
    lager:debug("Sending cipher data of size ~p to fsm", [Size]),
    lager:debug("Data is ~p bytes long", [byte_size(Data)]),
    Rest;
c_parse_chunk(Rest) ->
    lager:debug("No size match :("),
    Rest.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%
%% @spec terminate(Reason, StateName, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _StateName, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, StateName, State, Extra) ->
%%                   {ok, StateName, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
