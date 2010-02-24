% Service information
%
% type: fully qualified service type name
% name: fully qualified service name
% address: IP address as unsigned short, network byte order
% port: port that the service runs on
% weight: weight of the service
% priority: priority of the service
% properties: dictionary of properties (or a string holding the bytes for the text field)
% server: fully qualified name for service host (defaults to name)
-record(service, {
        type,
        name,
        address,
        port,
        weight=0,
        priority=0,
        properties,
        server
    }).

% Some timing constants

-define(UNREGISTER_TIME, 125).
-define(CHECK_TIME, 175).
-define(REGISTER_TIME, 225).
-define(LISTENER_TIME, 200).
-define(BROWSER_TIME, 500).

% Some DNS constants

-define(MDNS_ADDR, {224, 0, 0, 251}).
-define(MDNS_PORT, 5353).
-define(DNS_PORT, 53).
-define(DNS_TTL, 60 * 60). % one hour default TTL

-define(MAX_MSG_TYPICAL, 1460). % unused
-define(MAX_MSG_ABSOLUTE, 8972).

-define(FLAGS_QR_MASK, 16#8000). % query response mask
-define(FLAGS_QR_QUERY, 16#0000). % query
-define(FLAGS_QR_RESPONSE, 16#8000). % response

-define(FLAGS_AA, 16#0400). % Authorative answer
-define(FLAGS_TC, 16#0200). % Truncated
-define(FLAGS_RD, 16#0100). % Recursion desired
-define(FLAGS_RA, 16#8000). % Recursion available

-define(FLAGS_Z, 16#0040). % Zero
-define(FLAGS_AD, 16#0020). % Authentic data
-define(FLAGS_CD, 16#0010). % Checking disabled
