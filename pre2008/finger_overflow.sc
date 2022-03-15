if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17141" );
	script_version( "2021-01-20T08:41:35+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 08:41:35 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 2 );
	script_name( "fingerd buffer overflow" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "find_service1.sc", "find_service2.sc" );
	script_require_ports( "Services/finger", 79 );
	script_tag( name: "solution", value: "Disable the finger daemon, apply the latest patches from the
  vendor, or use a safer software." );
	script_tag( name: "summary", value: "The scanner was able to crash the remote finger daemon by sending a too long
  request." );
	script_tag( name: "impact", value: "This flaw is probably a buffer overflow and might be exploitable
  to run arbitrary code on this machine." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 79, proto: "finger" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: crap( 4096 ) + "\r\n" );
r = recv( socket: soc, length: 65535 );
close( soc );
sleep( 1 );
soc = open_sock_tcp( port );
if( !soc ){
	security_message( port: port );
	exit( 0 );
}
else {
	close( soc );
}
if(!r){
	report = "The remote finger daemon abruptly closes the connection when it receives a too long request. It might be vulnerable to an exploitable buffer overflow. ";
	report += "Note that the scanner did not crash the service, so this might be a false positive. However, if the finger service is run through inetd (a very common configuration), ";
	report += "it is impossible to reliably test this kind of flaw.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

