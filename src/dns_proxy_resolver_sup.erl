%%%-------------------------------------------------------------------
%%% @author Feather.et.ELF <andelf@gmail.com>
%%% @copyright (C) 2013, Feather.et.ELF
%%% @doc
%%%
%%% @end
%%% Created : 27 Apr 2013 by Feather.et.ELF <andelf@gmail.com>
%%%-------------------------------------------------------------------
-module(dns_proxy_resolver_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

-define(DNS_ADDRS, ["8.8.8.8", "8.8.4.4", 	% Google
		    "156.154.70.1", "156.154.71.1", % Dnsadvantage, returns bad
		    "4.2.2.1", "4.2.2.2", "4.2.2.3",
		    "4.2.2.4", "4.2.2.5", "4.2.2.6"]). %  GTEI DNS (now Verizon)


%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart frequency and child
%% specifications.
%%
%% @spec init(Args) -> {ok, {SupFlags, [ChildSpec]}} |
%%                     ignore |
%%                     {error, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    Pools = [{udp_resolver_pool, [{size, 10},
				  {max_overflow, 20}],
	      [{ip_pool, ?DNS_ADDRS}]},
	     {tcp_resolver_pool, [{size, 5},
		      {max_overflow, 10}],
	      [{hostname, "127.0.0.1"},
	       {database, "db2"},
	       {username, "db2"},
	       {password, "abc123"}]}],

    RestartStrategy = one_for_one,
    MaxRestarts = 10,
    MaxSecondsBetweenRestarts = 10,

    PoolSpecs = lists:map(fun({Name, SizeArgs, WorkerArgs}) ->
				  PoolArgs = [{name, {local, Name}},
					      {worker_module, example_worker}] ++ SizeArgs,
				  poolboy:child_spec(Name, PoolArgs, WorkerArgs)
			  end, Pools),
    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    %% Restart = permanent,
    %% Shutdown = 2000,
    %% Type = worker,

    {ok, {SupFlags, PoolSpecs}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
