%%%-------------------------------------------------------------------
%%% @author  <andelf@gmail.com>
%%% @copyright (C) 2013,
%%% @doc
%%%
%%% @end
%%% Created : 18 Apr 2013 by  <andelf@gmail.com>
%%%-------------------------------------------------------------------
-module(dns_proxy_srv).

-behaviour(gen_server).

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
   terminate/2, code_change/3]).

-compile([export_all]).

-define(SERVER, ?MODULE).

-record(state, {sock,table}).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("kernel/src/inet_dns.hrl").

-define(DEBUG(Term), io:format("debug: ~p~n", [Term])).
-define(DEBUG(What, Term), io:format("debug ~p: ~p~n", [What, Term])).

-define(DNS_ADDRS, ["8.8.8.8", "8.8.4.4", 	% Google
		    "156.154.70.1", "156.154.71.1", % Dnsadvantage
		    "4.2.2.1", "4.2.2.2", "4.2.2.3",
		    "4.2.2.4", "4.2.2.5", "4.2.2.6" %  GTEI DNS (now Verizon)
		    ]).

-define(FILE_STORE, "./resolve.ets").

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
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

test() ->
    Domain = "www.baidu.com",
    io:format("debug: ~p~n",
	      [ets:fun2ms(fun(#dns_rr{type=cname,domain=D}=R) when D =:= Domain -> R end)]).

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
    Tid = case ets:file2tab(?FILE_STORE) of
	      {ok, Table} ->
		  io:format("load table ~p from file~n", [Table]),
		  Table;
	      {error, _} ->
		  ets:new(resolve_table, [bag, public, named_table,
					  {keypos, #dns_rr.domain}])
    end,
    case gen_udp:open(53, [binary, {active, true}]) of
	{ok, Sock} ->
	    {ok, #state{sock=Sock, table=Tid}};
	{error, Reason} ->
	    {stop, Reason}
    end.

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
handle_info({udp, Sock, FromIP, FromPort, Data}, #state{sock=Sock,table=Tid} = State) ->
    io:format("got packet from ~p:~p~n", [FromIP, FromPort]),
    handle_dns_packet(Data, fun(D, normal) ->
				    gen_udp:send(Sock, FromIP, FromPort, D),
				    save_dns_result_to_table(Tid, D);
			       (D, cached) ->
				    gen_udp:send(Sock, FromIP, FromPort, D)
			    end, Tid),
    {noreply, State};
handle_info({test_ok, From}, #state{sock=Sock,table=Tid} = State) ->
    From ! ets:select(Tid, ets:fun2ms(fun(#dns_rr{type=cname,domain="www.baidu.com",data=Cname}=R) ->
					 Cname
				      end)),

    {noreply, State};
handle_info({udp_error,_Sock,econnreset}, State) ->
    io:format("!!! udp error ~p~n", [_Sock]),
    {noreply, State};
handle_info(_Info, State) ->
    io:format("unhandled message: ~p~n", [_Info]),
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
terminate(_Reason, #state{sock=Sock, table=Tid}) ->
    ets:tab2fie(Tid, ?FILE_STORE),
    gen_udp:close(Sock),
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
handle_dns_packet(Data, SendFunc, Tid) ->
    {ok, Packet} = inet_dns:decode(Data),
    #dns_rec{header=Header, qdlist=Questions, anlist=Answers,
	     nslist=Authorities, arlist=Resources} = Packet,
    handle_dns_header(Header),
    case Header#dns_header.qr of
	true ->
	    %% this is response
	    handle_dns_header(Header);
	false ->
	    %% this is a request
	    case query_table_by_dns_query(Tid, Questions) of
		[] ->
		    handle_dns_request(Packet, SendFunc);
		Cached ->
		    io:format("!!! found in cache! items=~p~n", [length(Cached)]),
                    %% io:format("got: ~p~n", [Cached]),
                    Packet1 = dns_rec_fill_answer(Packet, Cached),
                    Packet2 = dns_rec_set_rcode(Packet1, 0),
                    Packet3 = dns_rec_requst_to_response(Packet2),
		    SendFunc(inet_dns:encode(Packet3), cached)
	    end
    end,

    handle_dns_questions(Questions),
    %% io:format("got dns packet ~p~n", [Packet]),
    ok.

handle_dns_request(#dns_rec{header=#dns_header{qr=false,opcode='query'},
			    qdlist=Queries} = Packet,
		   SendFunc) ->
    QuerySendFunc =
	fun() ->
		Qdlist = lists:filter(fun(#dns_query{type=aaaa}) -> false;
					  (_)                     -> true
				       end,
				       Packet#dns_rec.qdlist),
		case Qdlist of
		    [] ->
			SendFunc(inet_dns:encode(dns_rec_requst_to_response(Packet)),
				 normal);
		    _  ->
			query_dns_and_send_response(Packet, SendFunc)
		end
	end,
    spawn(QuerySendFunc).

query_dns_and_send_response(Packet, SendFunc) ->
    {ok, S} = gen_udp:open(0, [binary]),
    {ok, DNSServerIP} = inet:ip(random_select(?DNS_ADDRS)),
    gen_udp:send(S, DNSServerIP, 53, inet_dns:encode(Packet)),
    receive
	{udp, S, DNSServerIP, 53, Data} ->
	    io:format("??? query ~p ok, sent response!~n", [DNSServerIP]),
	    SendFunc(Data, normal)
    after 2000 ->
	    io:format("### query ~p time out.~n", [DNSServerIP])
    end,
    gen_udp:close(S).


handle_dns_header(#dns_header{id=Id,qr=RespFlag,opcode=OpCode,rcode=RCode}) ->
    ok.


handle_dns_questions([#dns_query{domain=Domain,type=Type,class=Class}|Rest]) ->
    io:format("query type:~p ~p~n", [Type, Domain]),
    handle_dns_questions(Rest);
handle_dns_questions([]) ->
    ok.

handle_dns_answers([#dns_rr{domain=Domain,type=Type,class=Class,
			    cnt=Count,ttl=TTL,data=Data,tm=Time,
			    bm=_,func=_}|Rest]) ->
    io:format("dns record ~p ~p ~p~n", [Type, Class, Domain]),
    handle_dns_answers(Rest);
handle_dns_answers([]) ->
    ok.



save_dns_result_to_table(T, Data)    when is_binary(Data) ->
    {ok, Packet} = inet_dns:decode(Data),
    save_dns_result_to_table(T, Packet);
save_dns_result_to_table(T, Packet) when is_record(Packet, dns_rec) ->
    case Packet#dns_rec.anlist of
	[] ->
	    ok;
	Records ->
	    Records1 = lists:map(fun(R) -> dns_rr_set_ttl(R, 1000) end,
				 Records),
	    ets:insert(T, Records1)
    end.

query_table_by_dns_query(T, Query) when is_record(Query, dns_query) ->
    #dns_query{domain=Domain,type=Type,class=Class} = Query,
    Result = table_query(T, Domain),
    fill_cname_query(T, Result);
query_table_by_dns_query(T, [Query|Rest]=Queries) when is_list(Queries),
						       is_record(Query, dns_query) ->
    #dns_query{domain=Domain,type=Type,class=Class} = Query,
    lists:flatten([query_table_by_dns_query(T, Query),
		   query_table_by_dns_query(T, Rest)]);
query_table_by_dns_query(_, []) ->
    [].


fill_cname_query(Tid, [R|Rest]) ->
    #dns_rr{type=Type, domain=Domain, data=Data} = R,
    case Type of
	cname ->
	    [R|fill_cname_query(Tid, table_query(Tid, Data))] ++
		fill_cname_query(Tid, Rest);
	Other ->
	    [R|fill_cname_query(Tid, Rest)]
    end;
fill_cname_query(_, []) ->
    [].


table_query(Tid, Domain) ->
    %% fun2ms is bad here
    %% A = ets:select(Tid, [{{dns_rr,Domain,'_','_','_','_','_','_','_','_'},[],['$_']}]),
    A = ets:select(Tid, ets:fun2ms(fun(R=#dns_rr{domain=D}) when D =:= Domain -> R end)),
    A.

%% make ttl longer and store to a `bag`
dns_rr_set_ttl(Query, TTL) when is_record(Query, dns_rr), is_integer(TTL) ->
    Query#dns_rr{ttl=TTL}.

%% mac request code is not `0`
dns_rec_set_rcode(Response, RCode) when is_record(Response, dns_rec) ->
    Header = Response#dns_rec.header,
    Response#dns_rec{header=Header#dns_header{rcode=RCode}}.

dns_rec_requst_to_response(Packet) ->
    _OldHeader = Packet#dns_rec.header,
    Packet#dns_rec{header=_OldHeader#dns_header{qr=true}}.

dns_rec_fill_answer(Packet, Answers) when is_list(Answers) ->
    Packet#dns_rec{anlist=Answers}.

random_select(AList) ->
    random:seed(now()),
    lists:nth(random:uniform(length(AList)), AList).
