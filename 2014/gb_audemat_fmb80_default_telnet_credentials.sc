if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103898" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Audemat FMB80 RDS Encoder Default root Credentials" );
	script_xref( name: "URL", value: "http://dariusfreamon.wordpress.com/2014/01/28/audemat-fmb80-rds-encoder-default-root-credentials/" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-01-29 15:02:06 +0200 (Wed, 29 Jan 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Audemat FMB80 RDS Encoder has no or default credentials set." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the telnet service and, if needed, try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login without credentials or default credentials of root:root." );
	script_tag( name: "solution", value: "Change/Set the password." );
	script_tag( name: "solution_type", value: "Mitigation" );
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
recv = recv( socket: soc, length: 2048 );
if(!ContainsString( recv, "FMB80" )){
	exit( 0 );
}
if(ContainsString( recv, "User:" )){
	pass_needed = TRUE;
	send( socket: soc, data: "root\r\n" );
	recv = recv( socket: soc, length: 128 );
	if(!ContainsString( recv, "Password:" )){
		exit( 0 );
	}
	send( socket: soc, data: "root\r\n" );
	recv = recv( socket: soc, length: 128 );
	if(!ContainsString( recv, "Type HELP" )){
		exit( 99 );
	}
}
send( socket: soc, data: "USER?\r\n" );
recv = recv( socket: soc, length: 128 );
close( soc );
if(ContainsString( recv, "Root" )){
	if( pass_needed ) {
		report = "It was possible to login using the following credentials:\n\nroot:root\n";
	}
	else {
		report = "The remote telnet service is not protected by any credentials.";
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

