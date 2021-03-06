if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111061" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Zebra PrintServer Telnet Default Password" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-25 11:00:00 +0100 (Wed, 25 Nov 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Zebra PrintServer has a default password set." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the telnet service and try to login with a default password." );
	script_tag( name: "insight", value: "It was possible to login with default password 1234." );
	script_tag( name: "solution", value: "Change/Set the password." );
	script_xref( name: "URL", value: "https://support.zebra.com/cpws/docs/znet2/ps_firm/znt2_pwd.html" );
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
port = telnet_get_port( default: 23 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
recv = recv( socket: soc, length: 1024 );
if(ContainsString( recv, "ZebraNet" ) || ContainsString( recv, "Internal Wired PS Configuration Utility" ) || ContainsString( recv, "Type your password. Press Enter when finished." )){
	send( socket: soc, data: "1234\r\n" );
	recv = recv( socket: soc, length: 1024 );
	if(ContainsString( recv, "Show Configuration/Status" ) || ContainsString( recv, "Restore to Factory Defaults" ) || ContainsString( recv, "Specify Print Server IP Address" ) || ContainsString( recv, "TCP Connection Configuration" )){
		close( soc );
		security_message( port: port, data: "It was possible to login using the default password '1234'" );
		exit( 0 );
	}
}
close( soc );
exit( 99 );

