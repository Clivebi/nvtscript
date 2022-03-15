if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111051" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "APC Network Management Card Telnet Default Credentials" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-12 15:00:00 +0100 (Thu, 12 Nov 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote APC Network Management Card has default credentials set." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the telnet service and try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials of apc:apc or device:apc" );
	script_tag( name: "solution", value: "Change/Set the password." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
vuln = FALSE;
report = "It was possible to login using the following credentials:";
port = telnet_get_port( default: 23 );
creds = make_array( "apc", "apc", "device", "apc" );
for cred in keys( creds ) {
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	recv = recv( socket: soc, length: 2048 );
	if(ContainsString( recv, "User Name :" )){
		send( socket: soc, data: cred + "\r\n" );
		recv = recv( socket: soc, length: 128 );
		if(ContainsString( recv, "Password  :" )){
			send( socket: soc, data: creds[cred] + "\r\n" );
			recv = recv( socket: soc, length: 1024 );
			if(ContainsString( recv, "American Power Conversion" ) || ContainsString( recv, "Network Management Card" )){
				report += "\\n\\n" + cred + ":" + creds[cred] + "\\n";
				vuln = TRUE;
			}
		}
	}
	close( soc );
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

