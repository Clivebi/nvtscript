if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111092" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Brother Multiple Devices Telnet Default Password" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-26 18:12:12 +0100 (Sat, 26 Mar 2016)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/brother/device/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Brother Device has a default password set." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the telnet service and try to login with a default password." );
	script_tag( name: "insight", value: "It was possible to login with default password 'access' or without any password." );
	script_tag( name: "solution", value: "Change/Set the password." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
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
if(!banner || !ContainsString( banner, "Welcome. Type <return>, enter password at # prompt" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "\r\naccess\r\n\r\n" );
recv = recv( socket: soc, length: 512 );
send( socket: soc, data: "\r\n" );
recv = recv( socket: soc, length: 512 );
send( socket: soc, data: "show version\r\n" );
recv = recv( socket: soc, length: 512 );
close( soc );
if(ContainsString( recv, "Brother" )){
	security_message( port: port, data: "It was possible to login using the default password \"access\" or no password and any username." );
	exit( 0 );
}
exit( 99 );

