if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146591" );
	script_version( "2021-09-06T14:33:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 14:33:00 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-30 09:31:17 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "DNS Cache Snooping Vulnerability (UDP) - Active Check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "dns_server.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_require_udp_ports( "Services/udp/domain", 53 );
	script_tag( name: "summary", value: "The DNS server is prone to a cache snooping vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted DNS query and checks the response." );
	script_tag( name: "insight", value: "DNS cache snooping is when someone queries a DNS server in
  order to find out (snoop) if the DNS server has a specific DNS record cached, and thereby
  deduce if the DNS server's owner (or its users) have recently visited a specific site.

  This may reveal information about the DNS server's owner, such as what vendor, bank, service
  provider, etc. they use. Especially if this is confirmed (snooped) multiple times over a period.

  This method could even be used to gather statistical information - for example at what time does
  the DNS server's owner typically access his net bank etc. The cached DNS record's remaining TTL
  value can provide very accurate data for this.

  DNS cache snooping is possible even if the DNS server is not configured to resolve recursively
  for 3rd parties, as long as it provides records from the cache also to 3rd parties (a.k.a.
  'lame requests')." );
	script_tag( name: "impact", value: "Attackers might gain information about cached DNS records
  which might lead to further attacks.

  Note: This finding might be an acceptable risk if you:

  - trust all clients which can reach the server

  - do not allow recursive queries from outside your trusted client network." );
	script_tag( name: "solution", value: "There are multiple possible mitigation steps depending on
  location and funcionality needed by the DNS server:

  - Disable recursion

  - Don't allow public access to DNS Servers doing recursion

  - Leave recursion enabled if the DNS Server stays on a corporate network that cannot be reached
  by untrusted clients" );
	script_xref( name: "URL", value: "https://www.cs.unc.edu/~fabian/course_papers/cache_snooping.pdf" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-server-cache-snooping-attacks" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-00509" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-00482" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("port_service_func.inc.sc");
require("smtp_func.inc.sc");
port = service_get_port( default: 53, ipproto: "udp", proto: "domain" );
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
dom = get_3rdparty_domain();
domain = split( buffer: dom, sep: ".", keep: FALSE );
payload = "";
i = 0;
for part in domain {
	payload += raw_string( strlen( domain[i] ) ) + domain[i];
	i++;
}
id = rand() % 65535;
req = raw_string( mkword( id ), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, payload, 0x00, 0x00, 0x01, 0x00, 0x01 );
send( socket: soc, data: req );
recv = recv( socket: soc, length: 4096 );
close( soc );
if(isnull( recv ) || strlen( recv ) < 8 || getword( blob: recv, pos: 6 ) == 0){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
id = rand() % 65535;
req = raw_string( mkword( id ), 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, payload, 0x00, 0x00, 0x01, 0x00, 0x01 );
send( socket: soc, data: req );
recv = recv( socket: soc, length: 4096 );
close( soc );
if(isnull( recv ) || strlen( recv ) < 8 || getword( blob: recv, pos: 6 ) == 0){
	exit( 0 );
}
report = "Received (an) answer(s) for a non-recursive query for \"" + dom + "\".\n\nResult:\n\n";
pos = 24 + strlen( dom ) + 6;
ip = ord( recv[pos] ) + "." + ord( recv[pos + 1] ) + "." + ord( recv[pos + 2] ) + "." + ord( recv[pos + 3] );
report += ip;
security_message( port: port, data: report, proto: "udp" );
exit( 0 );

