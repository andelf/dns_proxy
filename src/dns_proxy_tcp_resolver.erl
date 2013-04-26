%%%-------------------------------------------------------------------
%%% @author Feather.et.ELF <andelf@gmail.com>
%%% @copyright (C) 2013, Feather.et.ELF
%%% @doc
%%%
%%% @end
%%% Created : 25 Apr 2013 by Feather.et.ELF <andelf@gmail.com>
%%%-------------------------------------------------------------------
-module(dns_proxy_tcp_resolver).

-behaviour(gen_server).

%% API
-export([start_link/1]).
-export([query_domain/1,
	 query_domain/2,
	 query_domain/3]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("kernel/src/inet_dns.hrl").
-define(SERVER, ?MODULE). 

-record(state, {sock,
		timeout}).

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
    %% register with name
    gen_server:start_link({local, ?SERVER}, ?MODULE, Args, []).
    %% gen_server:start_link(?MODULE, Args, []).


query_domain(Domain) ->
    query_domain(Domain, a).
query_domain(Domain, Type) ->
    query_domain(Domain, Type, in).
query_domain(Domain, Type, Class) ->
    %% make new dns_rec
    Id = random_id(),
    Packet = new_query_dns_rec(Id),
    %% fill dns_query
    Packet1 = Packet#dns_rec{qdlist=[#dns_query{domain=Domain, type=Type,
						class=Class}]},
    gen_server:call(?SERVER, {sync_send_dns_packet, Packet1}).

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
    {stop, "conf can't be empty"};
init(Args) ->
    {ok, IP} = inet:ip(proplists:get_value(ip, Args)),
    Port = proplists:get_value(port, Args, 53),
    Timeout = proplists:get_value(timeout, Args, 5000),
    {ok, Sock} = gen_tcp:connect(IP, Port, [binary,{active,false},
					   {keepalive, true}]),
    io:format("got sock ~p~n", [Sock]),
    {ok, #state{sock=Sock, timeout=Timeout}}.


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
handle_call({sync_send_dns_packet, Packet}, _From, State =
		#state{sock=Sock,timeout=Timeout}) when is_record(Packet, dns_rec) ->
    Id = (Packet#dns_rec.header)#dns_header.id,
    Raw = inet_dns:encode(Packet),
    ok = gen_tcp:send(Sock, <<(byte_size(Raw)):16, Raw/binary>>),
    io:format("waiting reply~n"),
    Reply = handle_dns_response(Sock, Id, Timeout),
    {reply, Reply, State}.


handle_dns_response(Sock, Id, Timeout) ->
    case catch receive_dns_response(Sock, Id, Timeout) of
	{ok, Packet} ->
	    Packet;
	{error, timeout} ->
	    {error, timeout};
	{'EXIT', _} = E->
	    %% skip bad packets in buffer
	    io:format("error ~p~n", [E]),
	    handle_dns_response(Sock, Id, Timeout)
    end.


receive_dns_response(Sock, Id, Timeout) ->
    {ok, <<Size:16>>} = gen_tcp:recv(Sock, 2, Timeout),
    io:format("size = ~p~n", [Size]),
    case gen_tcp:recv(Sock, Size) of
	{ok, Data} ->
	    {ok, Packet} = inet_dns:decode(Data, Timeout),
	    #dns_rec{header = #dns_header{id = Id, qr = true}} = Packet,
	    {ok, Packet};
	{error, timeout} ->
	    {error, timeout};
	{error, Other} ->
	    io:format("error ~p~n", [Other]),
	    {error, Other}
    end.
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
    io:format("info ~p~n", [_Info]),
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
new_query_dns_rec(Id) ->
    #dns_rec{header=#dns_header{id=Id,
				qr=false, %% query response
				opcode='query',
				aa=false, %% :1   authoritive answer
				tc=false, %% :1   truncated message
				rd=true,  %% :1   recursion desired 
				ra=false, %% :1   recursion available
				pr=false, %% :1   primary server required (non standard)
				rcode=0}, %% :4   response code
	     qdlist = [],  %% list of question entries
	     anlist = [],  %% list of answer entries
	     nslist = [],  %% list of authority entries
	     arlist = []   %% list of resource entries
	    }.


random_id() ->
    random:uniform(65535).

    
