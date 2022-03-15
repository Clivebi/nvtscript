if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103717" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "CAREL pCOWeb Default root Password" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-05-23 11:24:55 +0200 (Thu, 23 May 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/carel/pcoweb/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Login with telnet and change the password" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "summary", value: "The remote pCOWeb has the default password 'froot' for the root account." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to sensitive
  information or modify system configuration." );
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
if(!banner || !ContainsString( banner, "pCOWeb login" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = telnet_negotiate( socket: soc );
if(!ContainsString( buf, "pCOWeb login" )){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: "root\r\n" );
recv = recv( socket: soc, length: 4096 );
if(!ContainsString( recv, "Password:" )){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: "froot\r\n" );
recv = recv( socket: soc, length: 4096 );
if(!IsMatchRegexp( recv, "\\[root@pCOWeb.*root\\]#" )){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: "id\r\n" );
recv = recv( socket: soc, length: 8192 );
close( soc );
if(IsMatchRegexp( recv, "uid=0\\(root\\) gid=0\\(root\\)" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

