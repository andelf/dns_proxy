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
-export([start_link/0, query_domain/1, query_domain/2, query_domain/3]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

-define(DNS_ADDRS, ["8.8.8.8", "8.8.4.4", 	% Google
		    "156.154.70.1", "156.154.71.1", % Dnsadvantage, returns bad
		    "4.2.2.1", "4.2.2.2", "4.2.2.3",
		    "4.2.2.4", "4.2.2.5", "4.2.2.6"]). %  GTEI DNS (now Verizon)

-include_lib("kernel/src/inet_dns.hrl").

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


query_domain(Domain) ->
    query_domain(Domain, a).
query_domain(Domain, Type) ->
    query_domain(Domain, Type, in).
query_domain(Domain, Type, Class) ->
    query_domain(udp_resolver_pool, Domain, Type, Class).
query_domain(PoolName, Domain, Type, Class) ->
  

    Id = dns_utils:random_id(),
    Packet = dns_utils:new_query_dns_rec(Id),
    %% fill dns_query
    Packet1 = Packet#dns_rec{qdlist=[#dns_query{domain=Domain, type=Type,
						class=Class}]},
    %% PoolName = udp_resolver_pool,
    poolboy:transaction(PoolName,
			fun(Worker) ->
				gen_server:call(Worker, {sync_send_dns_packet, Packet1})
			end).


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
    Pools = [{udp_resolver_pool, [{worker_module, dns_proxy_udp_resolver},
				  {size, 10}, {max_overflow, 10}],
	      [{ip_pool, ?DNS_ADDRS}]},
	     {tcp_resolver_pool, [{worker_module, dns_proxy_tcp_resolver},
				  {size, 5}, {max_overflow, 10}],
	      [{ip_pool, ["202.106.196.115", "202.106.0.20"]}]}],

    RestartStrategy = one_for_one,
    MaxRestarts = 10,
    MaxSecondsBetweenRestarts = 10,
    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    PoolSpecs = lists:map(fun({Name, SizeArgs, WorkerArgs}) ->
				  PoolArgs = [{name, {local, Name}} | SizeArgs],
				  poolboy:child_spec(Name, PoolArgs, WorkerArgs)
			  end, Pools),

    io:format("~p~n", [PoolSpecs]),

    {ok, {SupFlags, PoolSpecs}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
