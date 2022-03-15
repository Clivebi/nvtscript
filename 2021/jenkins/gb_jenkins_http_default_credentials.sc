CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117453" );
	script_version( "2021-05-25T13:52:45+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-25 13:52:45 +0000 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-25 12:11:37 +0000 (Tue, 25 May 2021)" );
	script_name( "Jenkins Default Credentials (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_jenkins_consolidation.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "jenkins/http/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Jenkins automation server is using known default
  credentials for the web login." );
	script_tag( name: "vuldetect", value: "Tries to login via HTTP using known default credentials." );
	script_tag( name: "insight", value: "The remote Jenkins automation server is lacking a proper
  password configuration, which makes critical information and actions accessible for people with
  knowledge of the default credentials.

  Note: New Jenkins versions are creating / enforcing a strong and random password. But some
  specific deployments might still use known default credentials." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "solution", value: "Change the default password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("url_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
from_url = dir;
if(dir == "/"){
	dir = "";
}
creds = make_list( "admin:password",
	 "admin:admin",
	 "admin:jenkins",
	 "jenkins:jenkins" );
login_url = dir + "/login";
res = http_get_cache( port: port, item: login_url );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
report = "It was possible to login with the following known default credentials (username:password):\n";
urls = make_list( dir + "/j_spring_security_check",
	 dir + "/j_acegi_security_check" );
for cred in creds {
	split = split( buffer: cred, sep: ":", keep: FALSE );
	if(max_index( split ) != 2){
		continue;
	}
	username = split[0];
	password = split[1];
	for url in urls {
		req = http_get( port: port, item: login_url );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		sessionid = http_get_cookie_from_header( buf: res, pattern: "(JSESSIONID\\.[^=]+=[a-z0-9]+)" );
		if(!sessionid){
			continue;
		}
		headers = make_array( "Content-Type", "application/x-www-form-urlencoded", "Cookie", sessionid );
		if( ContainsString( url, "/j_spring_security_check" ) ) {
			post_data = "j_username=" + username + "&j_password=" + password + "&from=" + urlencode( str: from_url ) + "&Submit=Sign+in";
		}
		else {
			post_data = "j_username=" + username + "&j_password=" + password + "&from=" + urlencode( str: from_url ) + "&Submit=log+in";
		}
		req = http_post_put_req( port: port, url: url, data: post_data, add_headers: headers );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 302" )){
			continue;
		}
		sessionid = http_get_cookie_from_header( buf: res, pattern: "(JSESSIONID\\.[^=]+=[a-z0-9]+)" );
		if(!sessionid){
			continue;
		}
		req = http_get_req( port: port, url: from_url, add_headers: make_array( "Cookie", sessionid ) );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		if(ContainsString( res, "<title>Dashboard [Jenkins]</title>" ) && ContainsString( res, "<a href=\"/logout\">" )){
			VULN = TRUE;
			report += "\n" + username + ":" + password;
			break;
		}
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

