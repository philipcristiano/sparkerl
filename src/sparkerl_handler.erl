%%%-------------------------------------------------------------------
%%% @author $AUTHOR
%%% @copyright 2016 $OWNER
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------

-module(sparkerl_handler).

-compile([{parse_transform, lager_transform}]).


-export([init/0,
         handle_public_event/4]).

-record(state, {}).

init() ->
    {ok, #state{}}.

handle_public_event(Core, Name, Data, State) ->
    lager:info("Recieved handler public event! ~p", [{Core, Name, Data}]),
    {ok, State}.
