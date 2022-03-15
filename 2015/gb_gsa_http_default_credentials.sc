CPE = "cpe:/a:greenbone:greenbone_security_assistant";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105354" );
	script_version( "2021-07-22T11:56:11+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-22 11:56:11 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-09-14 14:47:11 +0200 (Mon, 14 Sep 2015)" );
	script_name( "Greenbone Security Assistant (GSA) Default Credentials (HTTP)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_gsa_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80, 443, 9392 );
	script_mandatory_keys( "greenbone_security_assistant/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Greenbone Security Assistant (GSA) is installed /
  configured in a way that it has account(s) with default passwords enabled." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Tries to login with known default credentials via the HTTP
  protocol." );
	script_tag( name: "solution", value: "Change the password of the mentioned account(s)." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
if( get_kb_item( "greenbone_security_assistant/" + port + "/gmp" ) ){
	url = dir + "/gmp";
	is_omp = FALSE;
}
else {
	url = dir + "/omp";
	is_omp = TRUE;
}
creds = make_array( "admin", "admin", "sadmin", "changeme", "Admin", "openvas", "aDmin", "adminpassword", "gvmadmin", "StrongPass", "observer", "observer", "webadmin", "webadmin", "gmp", "gmp", "omp", "omp" );
report = "It was possible to login using the following credentials (username:password):\n";
for username in keys( creds ) {
	password = creds[username];
	username = tolower( username );
	bound = rand();
	post_data = "-----------------------------" + bound + "\r\n" + "Content-Disposition: form-data; name=\"cmd\"\r\n" + "\r\n" + "login\r\n" + "-----------------------------" + bound + "\r\n";
	if(is_omp){
		post_data += "Content-Disposition: form-data; name=\"text\"\r\n" + "\r\n" + "/omp?r=1\r\n" + "-----------------------------" + bound + "\r\n";
	}
	post_data += "Content-Disposition: form-data; name=\"login\"\r\n" + "\r\n" + username + "\r\n" + "-----------------------------" + bound + "\r\n" + "Content-Disposition: form-data; name=\"password\"\r\n" + "\r\n" + password + "\r\n" + "-----------------------------" + bound + "--\r\n";
	referer_url = "/login";
	if(is_omp){
		referer_url += "/login.html";
	}
	headers = make_array( "Content-Type", "multipart/form-data; boundary=---------------------------" + bound );
	req = http_post_put_req( port: port, url: url, data: post_data, add_headers: headers, referer_url: referer_url, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if( is_omp ){
		if(!IsMatchRegexp( buf, "^HTTP/1\\.[01] 303" )){
			continue;
		}
		token = eregmatch( pattern: "token=([^\r\n \"]+)", string: buf );
		if(isnull( token[1] )){
			continue;
		}
	}
	else {
		if(!IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || IsMatchRegexp( buf, "Authentication required" )){
			continue;
		}
		token = eregmatch( pattern: "<token>([^<]+)</token>", string: buf );
		if(isnull( token[1] )){
			continue;
		}
	}
	cookie = eregmatch( pattern: "Set-Cookie: ([^\r\n]+)", string: buf );
	if(isnull( cookie[1] )){
		continue;
	}
	if( is_omp ){
		url += "?r=1&token=" + token[1];
		if(http_vuln_check( port: port, url: url, pattern: ">Logged in as", extra_check: make_list( ">Tasks<",
			 ">Targets<",
			 ">Logout<" ), cookie: cookie[1] )){
			vuln = TRUE;
			report += "\n" + username + ":" + password;
		}
	}
	else {
		if(ContainsString( buf, "<help_response status=\"200\" status_text=\"OK\">" ) || IsMatchRegexp( buf, "<role>.+</role>" ) || IsMatchRegexp( buf, "<session>.+</session>" )){
			vuln = TRUE;
			report += "\n" + username + ":" + password;
		}
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

