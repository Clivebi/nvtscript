if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108717" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-03-05 14:02:28 +0000 (Thu, 05 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "FTP Brute Force Logins" );
	script_category( ACT_ATTACK );
	script_family( "Brute force attacks" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/banner/available" );
	script_exclude_keys( "default_credentials/disable_brute_force_checks" );
	script_tag( name: "summary", value: "A number of weak/known credentials are tried for the login via the FTP protocol.

  As this VT might run into a timeout the actual reporting of this vulnerability takes place in the
  VT 'FTP Brute Force Logins Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108718)." );
	script_tag( name: "vuldetect", value: "Tries to login with a number of weak/known credentials via the FTP protocol." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_timeout( 900 );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_brute_force_checks" )){
	exit( 0 );
}
require("default_credentials.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
if(ftp_broken_random_login( port: port )){
	exit( 0 );
}
c = 0;
set_kb_item( name: "default_ftp_credentials/started", value: TRUE );
for credential in credentials {
	if(!soc = ftp_open_socket( port: port )){
		continue;
	}
	credential = str_replace( string: credential, find: "\\;", replace: "#sem_legacy#" );
	credential = str_replace( string: credential, find: "\\:", replace: "#sem_new#" );
	user_pass_type = split( buffer: credential, sep: ":", keep: FALSE );
	if(isnull( user_pass_type[0] ) || isnull( user_pass_type[1] )){
		user_pass_type = split( buffer: credential, sep: ";", keep: FALSE );
		if(isnull( user_pass_type[0] ) || isnull( user_pass_type[1] )){
			ftp_close( socket: soc );
			continue;
		}
	}
	type = user_pass_type[3];
	vendor = user_pass_type[2];
	if(!ContainsString( vendor, "custom" ) && !ContainsString( type, "ftp" )){
		ftp_close( socket: soc );
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
	login = ftp_authenticate( socket: soc, user: user, pass: pass, skip_banner: TRUE );
	ftp_close( socket: soc );
	if(login){
		c++;
		if(pass == ""){
			pass = "empty/no password";
		}
		set_kb_item( name: "default_ftp_credentials/" + port + "/credentials", value: user + ":" + pass );
		if(c >= 10){
			set_kb_item( name: "default_ftp_credentials/" + port + "/too_many_logins", value: c );
			break;
		}
	}
}
exit( 0 );

