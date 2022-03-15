if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113058" );
	script_version( "2020-04-09T12:09:29+0000" );
	script_tag( name: "last_modification", value: "2020-04-09 12:09:29 +0000 (Thu, 09 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-11-28 16:02:03 +0100 (Tue, 28 Nov 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "Opencast Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_opencast_detect.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "opencast/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Opencast is using default administrative credentials." );
	script_tag( name: "vuldetect", value: "The script tries to log in using the default credentials." );
	script_tag( name: "insight", value: "Opencast has a default administrative account called 'admin' with the password 'opencast'." );
	script_tag( name: "impact", value: "If unchanged, an attacker can use the default credentials to log in and gain administrative privileges." );
	script_tag( name: "affected", value: "All Opencast versions." );
	script_tag( name: "solution", value: "Change the 'admin' account's password." );
	script_xref( name: "URL", value: "https://docs.opencast.org/r/3.x/admin/configuration/basic/" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
CPE = "cpe:/a:opencast:opencast";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
req = http_get( port: port, item: dir + "/login.html" );
res = http_keepalive_send_recv( port: port, data: req );
cookie = http_get_cookie_from_header( buf: res, pattern: "JSESSIONID=([^; ]+)" );
if(isnull( cookie )){
	exit( 0 );
}
data = "j_username=admin&j_password=opencast&_spring_security_remember_me=on";
add_headers = make_array( "Cookie", "JSESSIONID=" + cookie, "Content-Type", "application/x-www-form-urlencoded" );
req = http_post_put_req( port: port, url: dir + "/j_spring_security_check", data: data, add_headers: add_headers );
res = http_keepalive_send_recv( port: port, data: req );
rememberme_cookie = http_get_cookie_from_header( buf: res, pattern: "SPRING_SECURITY_REMEMBER_ME_COOKIE=([^; ]+)" );
session_cookie = http_get_cookie_from_header( buf: res, pattern: "JSESSIONID=([^; ]+)" );
if(isnull( rememberme_cookie ) || isnull( session_cookie )){
	exit( 0 );
}
req = http_get_req( port: port, url: dir + "/index.html", add_headers: make_array( "Cookie", "JSESSIONID=" + session_cookie + "; SPRING_SECURITY_REMEMBER_ME_COOKIE=" + rememberme_cookie ) );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "translate=\"LOGOUT\"><!-- Logout--></span>" ) || ContainsString( res, "ng-show=\"services.error\">{{ services.numErr }}" ) )){
	report = "It was possible to log in to the Web Interface using the default user 'admin' with the default password 'opencast'.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

