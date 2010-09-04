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
    answers=[],
    socket
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
    set_socket(Pid, Socket),
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

set_socket(Pid, Socket) ->
    Pid ! {setsock, Socket}.

%% Main process loop.
receiver(#state{subscriptions=Sub}=State) ->
    receive
        {setsock, Socket} ->
            receiver(State#state{socket=Socket});
        {udp, Socket, _IP, _InPortNo, Packet} ->
            NewState = process_dnsrec(State, Socket, inet_dns:decode(Packet)),
            receiver(NewState);
        {reg, Pid, Service} ->
            NewState0 = process_reg(State, Service),
            Queries = [#dns_query{type=ptr, domain="_services._dns-sd._udp.local", class=in}],
            Out = #dns_rec{header=#dns_header{}, qdlist=Queries},
            gen_udp:send(State#state.socket, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Out)),
            NewState = process_dnsrec(NewState0, NewState0#state.socket, {ok, Out}),
            Pid ! {ok, NewState#state.services},
            receiver(NewState);
        {unreg, Pid, ServiceName} ->
            NewState = process_unreg(State, ServiceName),
            Pid ! {ok, NewState#state.services},
            receiver(NewState);
        {unreg_all, Pid, Service} ->
            NewState = process_unreg_all(State),
            receiver(NewState);
        {sub, Domain} ->
            Queries = [#dns_query{type=ptr, domain=Domain, class=in}, #dns_query{type=srv, domain=Domain, class=in}],
            Out = #dns_rec{header=#dns_header{}, qdlist=Queries},
            gen_udp:send(State#state.socket, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Out)),
            receiver(State#state{subscriptions=dict:store(Domain, dict:new(), Sub)});
        {unsub, Domain} ->
            receiver(State#state{subscriptions=dict:erase(Domain, Sub)});
        {getsubscriptions, Pid} ->
            Pid ! {ok, Sub},
            receiver(State);
        stop ->
            true;
        _AnythingElse ->
            receiver(State)
   end.

process_dnsrec(State, _Socket, {error, _E}) ->
    State;
process_dnsrec(#state{subscriptions=Sub, services=Services}=State, Socket, {ok, #dns_rec{qdlist=Queries, anlist=Responses, arlist=AResponses}}) ->
    case process_queries(Services, Queries) of
        ok -> ok;
        #dns_rec{anlist=Answers}=Out ->
            Out1 = Out#dns_rec{anlist=lists:reverse(Answers)},
            gen_udp:send(Socket, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Out1));
        _Else -> noop
    end,
    AllResponses = Responses ++ AResponses,
    State#state{subscriptions=dict:map(fun(K, V) -> process_responses(K, V, AllResponses) end, Sub)}.

register_service(Pid, #service{}=Service) ->
    Pid ! {reg, self(), Service},
    receive
        {ok, Reg} ->
            {ok, Reg}
    end.

unregister_service(Pid, ServiceName) ->
    Pid ! {unreg, self(), ServiceName},
    receive
        {ok, Reg} ->
            {ok, Reg}
    end.

unregister_all_services(Pid) ->
    Pid ! {unreg_all, self()}.

process_reg(#state{services=Services}=State, Service) ->
    State#state{services=[Service|Services]}.

process_unreg(#state{services=Services}=State, ServiceName) ->
    State#state{services=lists:filter(fun (#service{name=ServiceName}) -> false; (_) -> true end, Services)}.

process_unreg_all(#state{services=Services}=State) ->
    Out = #dns_rec{
        header=#dns_header{},
        anlist=lists:foldl(fun (#service{
            name=ServiceName,
            type=ServiceType,
            address=Address,
            priority=Prio,
            weight=Weight,
            port=Port,
            server=Server
        }, Acc) ->
            [#dns_rr{
                domain=ServiceType,
                type=ptr,
                ttl=0,
                data=ServiceName
            }, #dns_rr{
                domain=ServiceName,
                type=srv,
                ttl=0,
                data={Prio, Weight, Port, Server}
            } | Acc] end, [], Services)
    },
    gen_udp:send(State#state.socket, ?MDNS_ADDR, ?MDNS_PORT, inet_dns:encode(Out)),
    State#state{services=[]}.

process_queries(_Services, []) -> ok;
process_queries(Services, Queries) ->
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
        },
        Out2 = process_query(Services, Query#dns_query{type=srv, domain=Name}, Out1),
        process_query(Services, Query#dns_query{type=txt, domain=Name}, Out2)
    end, Out, Services);
process_query(Services, #dns_query{type=ptr, domain=Name}, #dns_rec{anlist=Answers}=Out) ->
    Out#dns_rec{anlist=lists:foldl(fun (#service{name=ServiceName}, Acc) -> [#dns_rr{
        domain=Name,
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
            properties=_Properties
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

process_response(#dns_rr{domain=Server, type=a, data=Address}, Services) ->
    dict:map(fun (_Key, #service{server=Server0}=Service) when Server == Server0-> Service#service{address=Address};
                 (_Key, Service) -> Service end, Services);
process_response(#dns_rr{domain=Name, type=srv, data={Prio, Weight, Port, Server}}, Services) ->
    F = fun (Service) -> Service#service{
        name=Name,
        priority=Prio,
        weight=Weight,
        port=Port,
        server=Server
    } end,
    dict:update(Name, F, F(#service{}), Services);
process_response(#dns_rr{domain=Type, type=ptr, data=Name, ttl=0}, Services) ->
    dict:erase(Name, Services);
process_response(#dns_rr{domain=Type, type=ptr, data=Name}, Services) ->
    F = fun (Service) -> Service#service{
        name=Name,
        type=Type
    } end,
    dict:update(Name, F, F(#service{}), Services);
process_response(_Else, Services) -> Services.

process_responses(_Domain, Services, Responses) ->
    lists:foldl(fun(R, Acc) -> process_response(R, Acc) end, Services, Responses).
