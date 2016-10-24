%%%-------------------------------------------------------------------
%%% @author Feather.et.ELF <andelf@gmail.com>
%%% @copyright (C) 2013, Feather.et.ELF
%%% @doc
%%%
%%% @end
%%% Created : 28 Apr 2013 by Feather.et.ELF <andelf@gmail.com>
%%%-------------------------------------------------------------------
-module(dns_utils).

%% API
-export([random_select/1, random_id/0, timestamp/0, timestamp/1,
	new_query_dns_rec/1]).

-include_lib("kernel/src/inet_dns.hrl").
%%%===================================================================
%%% API
%%%===================================================================

random_select(AList) ->
    rand:seed(erlang:timestamp()),
    lists:nth(rand:uniform(length(AList)), AList).


timestamp() ->
    timestamp(erlang:timestamp()).
timestamp({M,S,_}) ->
    M * 1000000 + S.

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
    rand:uniform(65535).



%%%===================================================================
%%% Internal functions
%%%===================================================================
