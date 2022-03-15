if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140241" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Default password `adminIWSS85` for admin account" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-04-10 15:23:54 +0200 (Mon, 10 Apr 2017)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote device is prone to a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login as admin with password 'adminIWSS85'." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
user = "admin";
pass = "adminIWSS85";
login = ssh_login( socket: soc, login: user, password: pass, priv: NULL, passphrase: NULL );
if(login == 0){
	cmd = ssh_cmd( socket: soc, cmd: "show system version", pattern: "IWSVA", pty: TRUE, nosh: TRUE, clear_buffer: TRUE );
	close( soc );
	if(ContainsString( cmd, "IWSVA:" ) && ContainsString( cmd, "Operating System:" )){
		report = "It was possible to login as user `admin` with password `adminIWSS85` and to execute the `show system version` command. Result:\n\n" + cmd;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(soc){
	close( soc );
}
exit( 0 );

