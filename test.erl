-module(test).
-include("emdns.hrl").

-export([test/0]).

test() ->
    {_Socket, Pid} = emdns:start(),
    emdns:subscribe(Pid, "_http._tcp.local"),
    emdns:register_service(Pid, #service{
        name="CouchDB._http._tcp.local",
        type="_http._tcp.local",
        address={127, 0, 0, 1},
        port=5984,
        server="jdd.local"
    }).
