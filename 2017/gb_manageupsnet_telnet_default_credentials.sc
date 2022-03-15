if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113049" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-11-09 15:05:05 +0100 (Thu, 09 Nov 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "ManageUPSNET UPS / USV Telnet Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/manageupsnet/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "ManageUPSNET Telnet and FTP uses remote credentials 'admin' - 'admin'." );
	script_tag( name: "vuldetect", value: "The script tries to login via Telnet using the username 'admin' and the password 'admin'." );
	script_tag( name: "impact", value: "Successful exploitation would allow to gain complete administrative access to the host." );
	script_tag( name: "affected", value: "All ManageUPSNET devices version 2.6 or later." );
	script_tag( name: "solution", value: "Change the default password for the administrative account 'admin' for both Telnet and FTP." );
	script_xref( name: "URL", value: "http://005c368.netsolhost.com/pdfs/9133161c.pdf" );
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
if(!banner || !ContainsString( banner, "ManageUPSnet" )){
	exit( 0 );
}
login = "admin";
pass = "admin";
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
recv = recv( socket: soc, length: 2048 );
if(ContainsString( recv, "User Name :" )){
	send( socket: soc, data: tolower( login ) + "\r\n" );
	recv = recv( socket: soc, length: 128 );
	if(ContainsString( recv, "Password  :" ) || ContainsString( recv, "Password :" )){
		send( socket: soc, data: pass + "\r\n\r\n" );
		recv = recv( socket: soc, length: 1024 );
		if(ContainsString( recv, "UPS Name:" ) && ContainsString( recv, "UPS Model:" )){
			VULN = TRUE;
			report = "It was possible to login via telnet using the following default credentials:\n\n";
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

