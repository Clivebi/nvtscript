if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108013" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2011-09-06 14:38:09 +0200 (Tue, 06 Sep 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSH Brute Force Logins With Default Credentials" );
	script_category( ACT_ATTACK );
	script_family( "Brute force attacks" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_brute_force_checks" );
	script_add_preference( name: "Seconds to wait between probes", value: "", type: "entry", id: 1 );
	script_timeout( 900 );
	script_tag( name: "summary", value: "A number of known default credentials are tried for the login via the SSH protocol.

  As this VT might run into a timeout the actual reporting of this vulnerability takes place in the
  VT 'SSH Brute Force Logins With Default Credentials Reporting' (OID: 1.3.6.1.4.1.25623.1.0.103239)." );
	script_tag( name: "vuldetect", value: "Tries to login with a number of known default credentials via the SSH protocol." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_brute_force_checks" )){
	exit( 0 );
}
require("default_credentials.inc.sc");
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
if(ssh_broken_random_login( port: port )){
	exit( 0 );
}
ssh_supported_authentication = get_kb_item( "SSH/supportedauth/" + port );
if(ssh_supported_authentication && IsMatchRegexp( ssh_supported_authentication, "^publickey$" )){
	exit( 0 );
}
c = 0;
d = script_get_preference( name: "Seconds to wait between probes", id: 1 );
if(int( d ) > 0){
	delay = int( d );
}
set_kb_item( name: "default_ssh_credentials/started", value: TRUE );
for credential in credentials {
	if(!soc = open_sock_tcp( port )){
		continue;
	}
	credential = str_replace( string: credential, find: "\\;", replace: "#sem_legacy#" );
	credential = str_replace( string: credential, find: "\\:", replace: "#sem_new#" );
	user_pass_type = split( buffer: credential, sep: ":", keep: FALSE );
	if(isnull( user_pass_type[0] ) || isnull( user_pass_type[1] )){
		user_pass_type = split( buffer: credential, sep: ";", keep: FALSE );
		if(isnull( user_pass_type[0] ) || isnull( user_pass_type[1] )){
			continue;
		}
	}
	type = user_pass_type[3];
	if(!ContainsString( type, "all" ) && !ContainsString( type, "ssh" )){
		continue;
	}
	user = chomp( user_pass_type[0] );
	pass = chomp( user_pass_type[1] );
	user = str_replace( string: user, find: "#sem_legacy#", replace: ";" );
	pass = str_replace( string: pass, find: "#sem_legacy#", replace: ";" );
	user = str_replace( string: user, find: "#sem_new#", replace: ":" );
	pass = str_replace( string: pass, find: "#sem_new#", replace: ":" );
	if(tolower( pass ) == "none"){
		pass = "";
	}
	login = ssh_login( socket: soc, login: user, password: pass, priv: NULL, passphrase: NULL );
	close( soc );
	if(login == "-2"){
		break;
	}
	if(login == 0){
		c++;
		if(pass == ""){
			pass = "empty/no password";
		}
		set_kb_item( name: "default_ssh_credentials/" + port + "/credentials", value: user + ":" + pass );
		if(c >= 10){
			set_kb_item( name: "default_ssh_credentials/" + port + "/too_many_logins", value: c );
			break;
		}
	}
	if( delay ){
		sleep( delay );
	}
	else {
		usleep( 50000 );
	}
}
exit( 0 );

