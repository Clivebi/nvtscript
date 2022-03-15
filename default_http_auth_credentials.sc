if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108041" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2011-09-06 14:38:09 +0200 (Tue, 06 Sep 2011)" );
	script_name( "HTTP Brute Force Logins With Default Credentials" );
	script_category( ACT_ATTACK );
	script_family( "Brute force attacks" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "gb_default_credentials_options.sc", "cgi_directories.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "www/content/auth_required" );
	script_exclude_keys( "default_credentials/disable_brute_force_checks" );
	script_timeout( 1800 );
	script_tag( name: "summary", value: "A number of known default credentials are tried for the login via HTTP Basic Auth.

  As this VT might run into a timeout the actual reporting of this vulnerability takes place in the
  VT 'HTTP Brute Force Logins With Default Credentials Reporting' (OID: 1.3.6.1.4.1.25623.1.0.103240)." );
	script_tag( name: "vuldetect", value: "Tries to login with a number of known default credentials via HTTP Basic Auth." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_brute_force_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
require("default_credentials.inc.sc");
func _check_response( res ){
	var res;
	if(res && !isnull( res ) && ( IsMatchRegexp( res, "^HTTP/1\\.[01] [0-9]+" ) ) && ( !IsMatchRegexp( res, "^HTTP/1\\.[01] 50[0234]" ) ) && ( !IsMatchRegexp( res, "^HTTP/1\\.[01] 40[0138]" ) ) && ( !IsMatchRegexp( res, "^HTTP/1\\.[01] 429" ) )){
		return TRUE;
	}
	return FALSE;
}
port = http_get_port( default: 80 );
kb_host = http_host_name( dont_add_port: TRUE );
if(!urls = http_get_kb_auth_required( port: port, host: kb_host )){
	exit( 0 );
}
set_kb_item( name: "default_http_auth_credentials/started", value: TRUE );
urls = nasl_make_list_unique( urls );
host = http_host_name( port: port );
useragent = http_get_user_agent();
for url in urls {
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 401" )){
		continue;
	}
	c = 0;
	for credential in credentials {
		if(c > 10){
			set_kb_item( name: "default_http_auth_credentials/" + kb_host + "/" + port + "/too_many_logins", value: c );
			exit( 0 );
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
		if(!ContainsString( type, "all" ) && !ContainsString( type, "http" )){
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
		if(tolower( user ) == "none"){
			user = "";
		}
		userpass = user + ":" + pass;
		userpass64 = base64( str: userpass );
		req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n", "\\r\\n" );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if( res && IsMatchRegexp( res, "^HTTP/1\\.[01] 30[0-8]" ) ){
			url = http_extract_location_from_redirect( port: port, data: res, current_dir: url );
			if(url){
				req = http_get( item: url, port: port );
				res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 401" )){
					req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n", "\\r\\n" );
					res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
					if(_check_response( res: res )){
						statuscode = egrep( pattern: "^HTTP/1\\.[01] [0-9]+( |$)", string: res );
						c++;
						set_kb_item( name: "default_http_auth_credentials/" + kb_host + "/" + port + "/credentials", value: url + "#-----#" + user + ":" + pass + ":" + chomp( statuscode ) );
					}
				}
			}
		}
		else {
			if(_check_response( res: res )){
				statuscode = egrep( pattern: "^HTTP/1\\.[01] [0-9]+( |$)", string: res );
				c++;
				set_kb_item( name: "default_http_auth_credentials/" + kb_host + "/" + port + "/credentials", value: url + "#-----#" + user + ":" + pass + ":" + chomp( statuscode ) );
			}
		}
	}
}
exit( 0 );

