if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105791" );
	script_version( "2021-06-21T08:57:39+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-21 08:57:39 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-06-30 17:36:06 +0200 (Thu, 30 Jun 2016)" );
	script_name( "Riverbed SteelCentral Default Credentials (SSH)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/openssh/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Riverbed SteelCentral system is using known default
  credentials for the SSH login." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Tries to login with the default credentials over SSH." );
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
banner = ssh_get_serverbanner( port: port );
if(!banner || !IsMatchRegexp( banner, "OpenSSH" )){
	exit( 0 );
}
users = make_list( "mazu",
	 "dhcp",
	 "root" );
pass = "bb!nmp4y";
for user in users {
	if(!soc = open_sock_tcp( port )){
		continue;
	}
	login = ssh_login( socket: soc, login: user, password: pass, priv: NULL, passphrase: NULL );
	if(login == 0){
		cmd = ssh_cmd( socket: soc, cmd: "id", nosh: TRUE );
		if(IsMatchRegexp( cmd, "uid=[0-9]+.+gid=[0-9]+" )){
			affected_users += user + "\n";
			cmd_result += cmd + "\n";
		}
	}
	close( soc );
}
if(affected_users){
	report = "It was possible to login and to execute the `id` command with the following users and the password `" + pass + "`\n\n" + affected_users + "\nid command result:\n" + cmd_result;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

