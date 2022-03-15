if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112104" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Actiontec C1000A Modem Backup Telnet Account" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-11-06 10:23:00 +0200 (Mon, 06 Nov 2017)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/actiontec/modem/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/43118/" );
	script_tag( name: "summary", value: "The Actiontec C1000A  modem has a backdoor account with hard-coded credentials." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain full
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the telnet service and try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with backup telnet credentials 'admin:CeturyL1nk'." );
	script_tag( name: "solution", value: "It is recommended to disable the telnet access." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Mitigation" );
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
if(!banner || !ContainsString( banner, "===Actiontec xDSL Router===" )){
	exit( 0 );
}
login = "admin";
pass = "CenturyL1nk";
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
recv = recv( socket: soc, length: 2048 );
if(ContainsString( recv, "Login:" )){
	send( socket: soc, data: login + "\r\n" );
	recv = recv( socket: soc, length: 128 );
	if(ContainsString( recv, "Password:" )){
		send( socket: soc, data: pass + "\r\n\r\n" );
		recv = recv( socket: soc, length: 1024 );
		send( socket: soc, data: "sh\r\n" );
		recv = recv( socket: soc, length: 1024 );
		if(ContainsString( recv, "BusyBox" ) && ContainsString( recv, "built-in shell" )){
			VULN = TRUE;
			report = "It was possible to login via telnet using the following backup credentials:\n\n";
			report += "Login: " + login + ", Password: " + pass;
		}
	}
}
close( soc );
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

