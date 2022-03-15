if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103726" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_name( "Unprotected Windows CE Telnet Console" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-03 12:36:40 +0100 (Mon, 03 Jun 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_ATTACK );
	script_family( "General" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "solution", value: "Set a password." );
	script_tag( name: "summary", value: "The remote Windows CE Telnet Console is not protected by a password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
buf = telnet_negotiate( socket: soc );
if(!ContainsString( buf, "Welcome to the Windows CE Telnet Service" ) && !ContainsString( buf, "Pocket CMD" ) && !ContainsString( buf, "\\>" )){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: "help\n" );
recv = recv( socket: soc, length: 512 );
send( socket: soc, data: "exit\n" );
close( soc );
if(ContainsString( recv, "The following commands are available:" ) && ContainsString( recv, "DEL" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

