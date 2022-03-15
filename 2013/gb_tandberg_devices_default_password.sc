if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103695" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Tandberg Devices Default Password" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2013-04-10 12:01:48 +0100 (Wed, 10 Apr 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_tandberg_devices_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( 23 );
	script_mandatory_keys( "host_is_tandberg_device" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "summary", value: "The remote Tandberg device has the default password 'TANDBERG'." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
port = 23;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = telnet_negotiate( socket: soc );
if(!ContainsString( buf, "Password:" )){
	exit( 0 );
}
send( socket: soc, data: "TANDBERG\n" );
recv = recv( socket: soc, length: 512 );
if(!ContainsString( recv, "OK" )){
	exit( 0 );
}
send( socket: soc, data: "ifconfig\n" );
recv = recv( socket: soc, length: 512 );
send( socket: soc, data: "exit\n" );
if(ContainsString( recv, "HWaddr" ) && ContainsString( recv, "Inet addr" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

