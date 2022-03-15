if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103860" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-12-18 11:44:04 +0200 (Wed, 18 Dec 2013)" );
	script_name( "IPmux-2L TDM Pseudowire Access Gateway Default Credentials" );
	script_xref( name: "URL", value: "http://dariusfreamon.wordpress.com/2013/12/17/ipmux-2l-tdm-pseudowire-access-gateway-default-credentials/" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/ipmux-2l/tdm/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "summary", value: "The remote IPmux-2L TDM Pseudowire Access Gateway
  is prone to a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "It was possible to login as user 'SU' with password '1234'." );
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
if(!banner || !ContainsString( banner, "IPmux-2L" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = recv( socket: soc, length: 4096 );
if(!ContainsString( buf, "IPmux-2L" )){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: "SU\r\n1234\r\n\r\n" );
buf = recv( socket: soc, length: 4096 );
close( soc );
if(ContainsString( buf, "main menu" ) && ContainsString( buf, "Inventory" ) && ContainsString( buf, "Configuration" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

