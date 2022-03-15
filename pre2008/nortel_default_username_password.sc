if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15715" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Nortel Default Username and Password" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_dependencies( "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Set a strong password for the account." );
	script_tag( name: "summary", value: "The username/password combination 'ro/ro' or 'rwa/rwa' are valid.

  These username and password are the default ones for many of
  Nortel's network devices." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
if(ssh_broken_random_login( port: port )){
	exit( 0 );
}
creds = make_array( "ro", "ro", "rwa", "rwa" );
report = "The following default credentials where identified: (user:pass)\n";
for cred in keys( creds ) {
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	ret = ssh_login( socket: soc, login: cred, password: creds[cred] );
	close( soc );
	if(ret == 0){
		VULN = TRUE;
		report += "\n" + cred + ":" + creds[cred];
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

