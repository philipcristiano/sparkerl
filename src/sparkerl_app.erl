-module(sparkerl_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_Type, _Args) ->
    {ok, _} = ranch:start_listener(spark_protocol, 100,
    	ranch_tcp, [{port, 5683}],
    	sparkerl_spark_protocol_fsm, []
    ),
	{ok, Pid} = sparkerl_sup:start_link(),
    {ok, Pid}.


stop(_State) ->
	ok.
