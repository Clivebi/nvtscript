if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105593" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Apache Karaf SSH Default Credentials" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-04-01 15:59:09 +0200 (Fri, 01 Apr 2016)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "os_detection.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 8101 );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Apache Karaf is prone to a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials: 'karaf/karaf'." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 8101 );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
user = "karaf";
pass = "karaf";
login = ssh_login( socket: soc, login: user, password: pass, priv: NULL, passphrase: NULL );
if(login == 0){
	files = traversal_files( "linux" );
	for pattern in keys( files ) {
		file = files[pattern];
		cmd = ssh_cmd( socket: soc, cmd: "cat /" + file, nosh: TRUE );
		if(egrep( string: cmd, pattern: pattern )){
			if(soc){
				close( soc );
			}
			report = "It was possible to login as user `karaf` with password `karaf` and to execute `cat /" + file + "`. Result:\n\n" + cmd;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
if(soc){
	close( soc );
}
exit( 99 );

