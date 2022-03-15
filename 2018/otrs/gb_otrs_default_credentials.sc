CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108465" );
	script_version( "2020-04-15T09:02:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-15 09:02:26 +0000 (Wed, 15 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-09-18 10:26:26 +0200 (Tue, 18 Sep 2018)" );
	script_name( "OTRS Default Credentials (HTTP)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "secpod_otrs_detect.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The OTRS instance is using known
  and default credentials for the HTTP based web interface." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to
  gain access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with known credentials." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
creds = make_array( "root@localhost", "root", "Root@localhost", "changeme" );
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.pl";
for cred in keys( creds ) {
	data = "Action=Login&RequestedURL=&Lang=en&TimeOffset=-120&User=" + tolower( cred ) + "&Password=" + creds[cred];
	add_headers = make_array( "Cookie", "OTRSBrowserHasCookie=1", "Content-Type", "application/x-www-form-urlencoded" );
	req = http_post_put_req( port: port, url: url, data: data, add_headers: add_headers );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	auth_token = http_get_cookie_from_header( buf: res, pattern: "OTRSAgentInterface=([^; ]+)" );
	if(isnull( auth_token )){
		continue;
	}
	req = http_get_req( port: port, url: url, add_headers: make_array( "Cookie", "OTRSAgentInterface=" + auth_token ) );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "Logout (You are logged in as Admin OTRS)" ) || IsMatchRegexp( res, "<title>Dashboard.*OTRS.*</title>" ) || IsMatchRegexp( res, "You are logged in as.*>Admin OTRS</a>" ) )){
		report = "It was possible to log in to the administrative web interface at '" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		report += "' using the default user '" + tolower( cred ) + "' with the default password '" + creds[cred] + "'.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

