%%%-------------------------------------------------------------------
%%% @author  <andelf@gmail.com>
%%% @copyright (C) 2013, 
%%% @doc
%%%
%%% @end
%%% Created : 22 Apr 2013 by  <andelf@gmail.com>
%%%-------------------------------------------------------------------
-module(dns_proxy_worker).

-behaviour(gen_server).


%% API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("kernel/src/inet_dns.hrl").

-define(SERVER, ?MODULE). 

-record(state, {sock, server_ip, server_port, id=9527}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    {stop, "no config"};
init(Args) ->
    ServerIP = inet:ip(proplists:get_value(ip, Args)),
    ServerPort = proplists:get_value(port, Args, 53),
    {ok, Sock} = gen_tcp:connect(ServerIP, 53, [binary,{active,false}]),
    {ok, #state{sock=Sock, server_ip=ServerIP, server_port=ServerPort}}.

%% QueryData = inet_dns:encode(new_dns_query(100, "baidu.com")),
%% io:format("send: ~p~n",
%% 	     [gen_tcp:send(Sock, <<(byte_size(QueryData)):16/integer, QueryData/binary>>)]),
%% {ok, <<Size:16>>} = gen_tcp:recv(Sock, 2, 5000),
%% {ok, Raw} = gen_tcp:recv(Sock, Size, 5000),
%% Packet = inet_dns:decode(Raw),
%% io:format("~p~n", [Packet]).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({'query', Domain, Class, Type}, _From, State = #state{sock=Sock, id=Id}) ->
    Packet = new_dns_query_packet(Id, Domain, Class, Type),
    Raw = inet_dns:encode(Packet),
    gen_tcp:send(Sock, <<(byte_size(Raw)):16, Raw/binary>>),
    {reply, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
new_dns_query_packet(Id, Domain, Type, Class) ->
    {dns_rec,{dns_header,Id,false,'query',false,false,true,false,false,0},
     [{dns_query,Domain,Type,Class}],
     [],[],[]}.

