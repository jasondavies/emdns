%%% Copyright 2010 Jason Davies
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License"); you may not
%%% use this file except in compliance with the License.  You may obtain a copy
%%% of the License at
%%%
%%%   http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
%%% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
%%% License for the specific language governing permissions and limitations
%%% under the License.

-module(emdns).
-include_lib("kernel/src/inet_dns.hrl").

-export([start/0, stop/1, receiver/1]).
-export([getsubscriptions/1, subscribe/2, unsubscribe/2, register_service/2]).

-include("emdns.hrl").

-record(state, {
    subscriptions=[],
    services=[],
    answers=[]
    }).

%% Gets a timestamp in milliseconds.
get_timestamp() ->
    {Mega, Sec, Micro} = erlang:now(),
    (Mega * 1000000 + Sec) * 1000000 + Micro.

%% Starts the process listening for mDNS messages.
start() ->
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

%% Stops the process listening for mDNS messages.
stop({S, Pid}) ->
   gen_udp:close(S),
   Pid ! stop.

%% Subscribes to a domain.
subscribe(Pid, Domain) -> Pid ! {sub, Domain}.

%% Unsubscribes from a domain.
unsubscribe(Pid, Domain) -> Pid ! {unsub, Domain}.

%% Gets a list of domains currently subscribed to.
getsubscriptions(Pid) ->
    Pid ! {getsubscriptions, self()},
    receive
        {ok, Sub} ->
            {ok, Sub}
    end.

%% Main process loop.
receiver(#state{subscriptions=Sub}=State) ->
    receive
        {udp, Socket, _IP, InPortNo, Packet} ->
            io:format("INPORT: ~p~n", [InPortNo]),
            NewState = process_dnsrec(State, Socket, inet_dns:decode(Packet)),
            receiver(NewState);
        {reg, Pid, Service} ->
            NewState = process_reg(State, Service),
            Pid ! {ok, NewState#state.services},
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
    io:format("Error: ~p~n", [E]),
    State;
process_dnsrec(#state{subscriptions=Sub, services=Services}=State, Socket, {ok, #dns_rec{qdlist=Queries, anlist=Responses}}) ->
    case process_queries(Services, Queries) of
        ok -> ok;
        #dns_rec{anlist=Answers}=Out ->
            io:format("SENDING: ~p~n",[Out]),
            Out1 = Out#dns_rec{anlist=lists:reverse(Answers)},
            gen_udp:send(Socket, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Out1))
    end,
    State#state{subscriptions=dict:map(fun(X, V) -> process_responses(X, V, Responses) end, Sub)}.

register_service(Pid, #service{}=Service) ->
    Pid ! {reg, self(), Service},
    receive
        {ok, Reg} ->
            {ok, Reg}
    end.

process_reg(#state{services=Services}=State, Service) ->
    State#state{services=[Service|Services]}.

process_queries(_Services, []) -> ok;
process_queries(Services, Queries) ->
    io:format("Queries: ~p~n",[Queries]),
    _Reg = ["_services._dns-sd._udp.local", "_http._tcp.local"],
    %lists:foreach(fun(Q) -> case lists:member(Q#dns_query.domain,Reg) of
    %                            true -> io:format("HIT: ~p~n",[Q]);
    %                            false -> io:format("MISS: ~p~n",[Q])
    %                        end
    %              end, Queries),
    lists:foldl(fun(Q, Out) -> process_query(Services, Q, Out) end, #dns_rec{
        header=#dns_header{qr=1, aa=1},
        qdlist=[]
    }, Queries).
    %[process_query(S, Queries, Q) || Q <- Queries, lists:member(Q#dns_query.domain,Reg)].

% Special case: http://developer.apple.com/mac/library/qa/qa2004/qa1337.html
process_query(Services, #dns_query{type=ptr, domain="_services._dns-sd._udp.local"}=Query, Out) ->
    lists:foldl(fun (#service{name=Name, type=Type}, #dns_rec{anlist=Answers}=Out0) ->
        Out1 = Out0#dns_rec{
            anlist=[#dns_rr{
                domain=Type,
                type=ptr,
                ttl=?DNS_TTL,
                data=Name
            }, #dns_rr{
                domain="_services._dns-sd._udp.local",
                type=ptr,
                ttl=?DNS_TTL,
                data=Type
            } | Answers]
        }%,
        %Out2 = process_query(Services, Query#dns_query{type=srv, domain=Name}, Out1),
        %process_query(Services, Query#dns_query{type=txt, domain=Name}, Out2)
    end, Out, Services);
process_query(Services, #dns_query{type=ptr, domain=Name}, #dns_rec{anlist=Answers}=Out) ->
    Out#dns_rec{anlist=lists:foldl(fun (#service{name=ServiceName}, Acc) -> [#dns_rr{
        type=ptr,
        ttl=?DNS_TTL,
        data=ServiceName
    } | Acc] end, Answers, lists:filter(fun (#service{type=ServiceType}) -> Name == ServiceType end, Services))};
%% Answer A record queries for any service addresses we know
process_query(Services, #dns_query{type=a, domain=Name}, #dns_rec{anlist=Answers}=Out) ->
    Out#dns_rec{anlist=lists:foldl(fun (#service{address=ServiceAddr}, Acc) -> [#dns_rr{
        type=a,
        ttl=?DNS_TTL,
        data=ServiceAddr
    } | Acc] end, Answers, lists:filter(fun (#service{server=Server}) -> string:to_lower(Name) == Server end, Services))};
process_query(Services, #dns_query{type=srv, domain=Name}, #dns_rec{anlist=Answers, arlist=AdditionalAnswers}=Out) ->
    case get_service(Services, string:to_lower(Name)) of
        #service{
            address=Address,
            priority=Prio,
            weight=Weight,
            port=Port,
            server=Server
        } ->
            Out#dns_rec{anlist=[#dns_rr{
                    domain=Name,
                    type=srv,
                    ttl=?DNS_TTL,
                    data={Prio, Weight, Port, Server}
                } | Answers],
                arlist=[#dns_rr{
                    domain=Server,
                    type=a,
                    ttl=?DNS_TTL,
                    data=Address
                } | AdditionalAnswers]
            };
        _ -> Out
    end;
process_query(Services, #dns_query{type=txt, domain=Name}, #dns_rec{anlist=Answers}=Out) ->
    case get_service(Services, string:to_lower(Name)) of
        #service{
            properties=Properties
        } ->
            Out#dns_rec{anlist=[#dns_rr{
                domain=Name,
                type=txt,
                ttl=?DNS_TTL,
                data=["TESTTXT JASON"]
            } | Answers]};
        _ -> Out
    end;
process_query(Services, #dns_query{type=any}=Query, Out0) ->
    Out1 = process_query(Services, Query#dns_query{type=a}, Out0),
    Out2 = process_query(Services, Query#dns_query{type=srv}, Out1),
    process_query(Services, Query#dns_query{type=txt}, Out2);
process_query(_Services, _Query, Out) -> Out.

get_service([#service{name=ServiceName}=Service | Services], Name) ->
    case string:to_lower(ServiceName) of
        Name -> Service;
        _ -> get_service(Services, Name)
    end;
get_service([], _Name) -> undefined.

%
%    H = #dns_header{qr=1,aa=1},
%    D = "CouchDB._http._tcp.local",
%    R = #dns_rr{domain="_http._tcp.local",type=ptr,ttl=Ttl,data=D},
%    Rec = #dns_rec{header=H,anlist=[R],qdlist=[]},%Queries},
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
%    Prio = 0,
%    Weight = 0,
%    Port = 5984,
%    Rec1 = #dns_rec{header=H,anlist=[
%            #dns_rr{domain=D,type=srv,ttl=Ttl,data={Prio, Weight, Port, "jdd.local"}},
%            #dns_rr{domain=D,type=txt,ttl=Ttl,data=["TESTTXT"]}
%        ],
%        arlist=[
%            #dns_rr{domain="jdd.local",type=a,ttl=Ttl,data={127,0,0,1}}
%        ],qdlist=[]},
%    gen_udp:send(S, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Rec)),
%    gen_udp:send(S, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Rec1)).
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

%% Normalize single boolean key value entries
%% make "key" == "key=true"
%% make "key=" == "key=[]"
normalize_kv(T) ->
    case re:split(T,"=",[{return,list}]) of
        [K] -> {K,true};
        [K,V] -> {K,V}
    end.
