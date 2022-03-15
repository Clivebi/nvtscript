if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105452" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "SolarWinds Log and Event Manager cmc SSH Default Credentials" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-13 19:06:56 +0100 (Fri, 13 Nov 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 32022 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote SolarWinds Log and Event Manager is prone to a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials: 'cmc/password'." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 32022 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
user = "cmc";
pass = "password";
login = ssh_login( socket: soc, login: user, password: pass, priv: NULL, passphrase: NULL );
if(login == 0){
	buf = ssh_cmd( socket: soc, cmd: "exit", nosh: TRUE, pty: TRUE, pattern: "cmc>" );
	close( soc );
	if(ContainsString( buf, "CMC Build" )){
		security_message( port: port );
		exit( 0 );
	}
}
if(soc){
	close( soc );
}
exit( 99 );

