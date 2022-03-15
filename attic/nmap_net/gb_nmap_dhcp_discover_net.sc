if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104065" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: dhcp-discover" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Sends a DHCPDISCOVER request to a host on UDP port 67. The response comes back to UDP port 68, and
is read using pcap (due to the inability for a script to choose its source port at the moment).

DHCPDISCOVER is a DHCP request that returns useful information from a DHCP server. The request sends
a list of which fields it wants to know (a handful by default, every field if verbosity is turned
on), and the server responds with the fields that were requested. It should be noted that the server
doesn't have to return every field, nor does it have to return them in the same order, or honour the
request at all. A Linksys WRT54g, for example, completely ignores the list of requested fields and
returns a few  standard ones. This script displays every field it receives.

With script arguments, the type of DHCP request can be changed, which can lead to interesting
results.  Additionally, the MAC address can be randomized, which should override the cache on the
DHCP server and assign a new IP address. Extra requests can also be sent to exhaust the IP address
range more quickly.

DHCPINFORM is another type of DHCP request that requests the same information, but doesn't reserve
an address. Unfortunately, because many home routers simply ignore DHCPINFORM requests, we opted to
use DHCPDISCOVER instead.

Some of the more useful fields: * DHCP Server (the address of the server that responded) * Subnet
Mask * Router * DNS Servers * Hostname

SYNTAX:

fake_requests:  Set to an integer to make that many fake requests  before the real one(s).
This could be useful, for example, if you  also use 'randomize_mac'
and you want to try exhausting  all addresses.


requests:  Set to an integer to make up to  that many requests (and display the results).


randomize_mac:  Set to 'true' or '1' to  send a random MAC address with
the request (keep in mind that you may  not see the response). This should
cause the router to reserve a new  IP address each time.


dhcptype:  The type of DHCP request to make. By default, DHCPDISCOVER is sent, but this
argument can change it to DHCPOFFER, DHCPREQUEST, DHCPDECLINE, DHCPACK, DHCPNAK,
DHCPRELEASE or DHCPINFORM. Not all types will evoke a response from all servers,
and many require different fields to contain specific values." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

