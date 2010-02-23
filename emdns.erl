% Copyright 2010 Jason Davies
%
% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License.  You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
% License for the specific language governing permissions and limitations under
% the License.

-module(emdns).
-include("emdns.hrl").
-include_lib("kernel/src/inet_dns.hrl").

-export([start/0, stop/1, receiver/1]).
-export([getsubscriptions/1, subscribe/2, unsubscribe/2, register_service/8]).
-export([send/0, send/1]).

-record(state, {
    subscriptions,
    services,
    answers
    }).

send(Domain) ->
    {ok,S} = gen_udp:open(5353,[{reuseaddr,true}, {ip,{224,0,0,251}}, {multicast_ttl,4}, {multicast_loop,false}, {broadcast,true}, binary]),
    P = #dns_rec{header=#dns_header{},qdlist=[#dns_query{domain=Domain,type=ptr,class=in}]},
    gen_udp:send(S,{224,0,0,251},5353,inet_dns:encode(P)),
    gen_udp:close(S).

send() ->
    H = #dns_header{qr=1,aa=1},
    {ok,HN} = inet:gethostname(),
    D = "test@" ++ HN ++ "._test._tcp.local",
    R = #dns_rr{domain="_test._tcp.local",type=ptr,ttl=4500,data=D},
    Rec = #dns_rec{header=H,anlist=[R]},
    {ok,S}=gen_udp:open(0,[]),
    inet:setopts(S, [{reuseaddr,true},{broadcast,true}]),
    gen_udp:send(S,?MDNS_ADDR,?MDNS_PORT,inet_dns:encode(Rec)).

% Get a timestamp in ms from the epoch 1970-01-01
get_timestamp() ->
    {Mega, Sec, Micro} = erlang:now(),
    (Mega * 1000000 + Sec) * 1000000 + Micro.

start() ->
    % start the process listening for mdns messages
    %BindAddress = ,
    %Intf = ,
    %Group = {"", ?MDNS_PORT},
    LAddr = {127, 0, 0, 1},
    {ok, Socket} = gen_udp:open(?MDNS_PORT, [
        {reuseaddr, true},
        {ip, ?MDNS_ADDR},
        {multicast_ttl, 255},
        {multicast_loop, true},
        {multicast_if, LAddr},
        {broadcast, true},
        binary
    ]),
    inet:setopts(Socket, [
        {add_membership, {?MDNS_ADDR, {0, 0, 0, 0}}}
    ]),
    Pid = spawn(?MODULE, receiver, [#state{subscriptions=dict:new()}]),
    gen_udp:controlling_process(Socket, Pid),
    {Socket, Pid}.

stop({S,Pid}) ->
   gen_udp:close(S),
   Pid ! stop.

subscribe(Domain,Pid) -> Pid ! {sub, Domain}.

unsubscribe(Domain,Pid) -> Pid ! {unsub, Domain}.

getsubscriptions(Pid) ->
    Pid ! {getsubscriptions, self()},
    receive
        {ok, Sub} ->
            {ok, Sub}
    end.

receiver(#state{subscriptions=Sub}=State) ->
    receive
        {udp, Socket, _IP, _InPortNo, Packet} ->
            NewState = process_dnsrec(State, Socket, inet_dns:decode(Packet)),
            receiver(NewState);
        {reg, _Pid, Info} ->
            NewState = process_reg(State, Info),
            receiver(NewState);
        {sub, Domain} ->
            receiver(State#state{subscriptions=dict:store(Domain, dict:new(), Sub)});
        {unsub, Domain} ->
            receiver(State#state{subscriptions=dict:erase(Domain, Sub)});
        {getsubscriptions, Pid} ->
            Pid ! {ok, Sub},
            receiver(State);
        stop ->
            true;
        AnythingElse ->
            io:format("RECEIVED: ~p~n", [AnythingElse]),
            receiver(State)
   end.

process_dnsrec(State, _Socket, {error, E}) ->
    io:format("Error: ~p~n", [E]), % TODO: Improve error handling
    State;
process_dnsrec(#state{subscriptions=Sub}=State, Socket, {ok, #dns_rec{qdlist=Queries, anlist=Responses}}) ->
    process_queries(Socket, Queries),
    State#state{subscriptions=dict:map(fun(X, V) -> process_responses(X, V, Responses) end, Sub)}.

register_service(Pid, Domain, Name, Addr, Port, Weight, Priority, Props) ->
    Pid ! {reg, self(), {Domain, Name, Addr, Port, Weight, Priority, Props}},
    receive
        {ok, Reg} ->
            {ok, Reg}
    end.

process_reg(State, {Domain, Name, Addr, Port, Weight, Priority, Props}) ->
    State.

process_queries(_S,[]) -> ok;
process_queries(S,Queries) ->
    io:format("Queries: ~p~n",[Queries]),
    Reg = ["_services._dns-sd._udp.local", "_http._tcp.local"],
    lists:foreach(fun(Q) -> case lists:member(Q#dns_query.domain,Reg) of
                                true -> io:format("HIT: ~p~n",[Q]);
                                false -> io:format("MISS: ~p~n",[Q])
                            end
                  end, Queries),
    [process_query(S, Queries, Q) || Q <- Queries, lists:member(Q#dns_query.domain,Reg)].

% Special case: http://developer.apple.com/mac/library/qa/qa2004/qa1337.html
process_query(S, Queries, #dns_query{domain="_services._dns-sd._udp.local"}) ->
    Rec = #dns_rec{
        header=#dns_header{qr=1, aa=1},
        anlist=[
            #dns_rr{
                domain="_services._dns-sd._udp.local",
                type=ptr,
                ttl=?DNS_TTL,
                data="_http._tcp.local"
            }
        ],
        qdlist=[]
    },
    gen_udp:send(S, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Rec));
process_query(S, Queries, Query) ->
    io:format("Registered Query: ~p~n",[Query]),
    Ttl=?DNS_TTL,
    H = #dns_header{qr=1,aa=1},
    D = "CouchDB._http._tcp.local",
    R = #dns_rr{domain="_http._tcp.local",type=ptr,ttl=Ttl,data=D},
    Rec = #dns_rec{header=H,anlist=[R],qdlist=[]},%Queries},
    LAddr = {127, 0, 0, 1},
    %{ok, S} = gen_udp:open(?MDNS_PORT, [
        %{active, false},
    %    {reuseaddr, true},
        %{ip, ?MDNS_ADDR},
    %    {ip, LAddr},
    %    {multicast_if, {0, 0, 0, 0}},
    %    {multicast_ttl, 255},
    %    {multicast_loop, true},
        %{broadcast, true},
    %    binary
    %]),
    %inet:setopts(S, [
    %    {add_membership, {?MDNS_ADDR, {0, 0, 0, 0}}}
    %]),
    Prio = 0,
    Weight = 0,
    Port = 5984,
    Rec1 = #dns_rec{header=H,anlist=[
            #dns_rr{domain=D,type=srv,ttl=Ttl,data={Prio, Weight, Port, "jdd.local"}},
            #dns_rr{domain=D,type=txt,ttl=Ttl,data=["TESTTXT"]}
        ],
        arlist=[
            #dns_rr{domain="jdd.local",type=a,ttl=Ttl,data={127,0,0,1}}
        ],qdlist=[]},
    gen_udp:send(S, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Rec)),
    gen_udp:send(S, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Rec1)).
    %gen_udp:close(S).
process_responses(S, Value, Responses) ->
    io:format("Responses ~p~n",[Responses]),
    lists:foldl(fun(#dns_rr{domain = Domain} = Response, Val) ->
        process_response(lists:suffix(S, Domain), Response, Val) end, Value, Responses).

process_response(false, _Response, Val) -> Val;
process_response(true, #dns_rr{ttl=TTL} = _Response, _Val) when TTL == 0 ->
    %% the server left and lets us know this because TTL == Zero
    dict:new();
process_response(true, #dns_rr{domain = Domain, type = Type, class = Class} = Response, Val) when Type == txt ->
    DTXT = lists:foldl(fun(T,D) -> {K,V} = normalize_kv(T),dict:store(K,V,D) end,dict:new(),Response#dns_rr.data),
    NewRR = Response#dns_rr{tm=get_timestamp(),data=DTXT},
    dict:store({Domain,Type,Class},NewRR,Val);
process_response(true, #dns_rr{domain = Domain, type = Type, class = Class} = Response, Val) ->
    NewRR = Response#dns_rr{tm=get_timestamp()},
    dict:store({Domain,Type,Class},NewRR,Val).

normalize_kv(T) ->
    %% normalize single boolean key value entries
    %% make "key" == "key=true"
    %% make "key=" == "key=[]"
    case re:split(T,"=",[{return,list}]) of
        [K] -> {K,true};
        [K,V] -> {K,V}
    end.
