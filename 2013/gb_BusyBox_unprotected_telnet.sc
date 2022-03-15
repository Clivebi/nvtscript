if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103696" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Unprotected BusyBox Telnet Console" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-04-11 12:36:40 +0100 (Thu, 11 Apr 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/busybox/console/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Set a password." );
	script_tag( name: "summary", value: "The remote BusyBox Telnet Console is not protected by a password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || ( !ContainsString( banner, "BusyBox" ) && !ContainsString( banner, "list of built-in commands" ) )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = telnet_negotiate( socket: soc );
if(!ContainsString( buf, "BusyBox" ) && !ContainsString( buf, "list of built-in commands" )){
	exit( 0 );
}
send( socket: soc, data: "id\n" );
recv = recv( socket: soc, length: 512 );
send( socket: soc, data: "exit\n" );
close( soc );
if(IsMatchRegexp( recv, "uid=[0-9]+.*gid=[0-9]+.*" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

