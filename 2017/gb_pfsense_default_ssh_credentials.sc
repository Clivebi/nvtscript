if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112123" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-11-15 13:32:16 +0100 (Wed, 15 Nov 2017)" );
	script_name( "pfSense Default Credentials (SSH)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "os_detection.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "pfSense is prone to a default account authentication bypass vulnerability via SSH." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to sensitive information
  or modify the system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with known credentials." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "exploit" );
	script_xref( name: "URL", value: "https://www.question-defense.com/2012/11/19/pfsense-default-login" );
	script_xref( name: "URL", value: "https://doc.pfsense.org/index.php/HOWTO_enable_SSH_access" );
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
port = ssh_get_port( default: 22 );
password = "pfsense";
report = "It was possible to login to pfSense via SSH with the following credentials:\n";
files = traversal_files( "linux" );
for username in make_list( "admin",
	 "root" ) {
	if(!soc = open_sock_tcp( port )){
		exit( 0 );
	}
	login = ssh_login( socket: soc, login: username, password: password, priv: NULL, passphrase: NULL );
	if(login == 0){
		for pattern in keys( files ) {
			file = files[pattern];
			rcv = ssh_cmd( socket: soc, cmd: "8\n && cat /" + file, nosh: TRUE, pty: TRUE );
			if(ContainsString( rcv, "Welcome to pfSense" ) && egrep( string: rcv, pattern: pattern )){
				vuln = TRUE;
				report += "\nUsername: \"" + username + "\", Password: \"" + password + "\"";
			}
			if(passwd = egrep( pattern: pattern, string: rcv )){
				passwd_report += "\nIt was also possible to execute \"cat /" + file + "\" as \"" + username + "\". Result:\n\n" + passwd;
			}
		}
	}
	close( soc );
}
if(vuln){
	if(passwd_report){
		report += "\n" + passwd_report;
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

