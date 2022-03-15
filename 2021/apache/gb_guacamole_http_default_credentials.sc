CPE = "cpe:/a:apache:guacamole";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117610" );
	script_version( "2021-08-04T11:10:17+0000" );
	script_tag( name: "last_modification", value: "2021-08-04 11:10:17 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-04 10:19:36 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Apache Guacamole Default Credentials (HTTP)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_guacamole_http_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache/guacamole/http/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Apache Guacamole instance is using known default
  credentials for the HTTP login." );
	script_tag( name: "vuldetect", value: "Tries to login via HTTP using known default credentials." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "affected", value: "All Apache Guacamole instances with default credentials." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
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
creds = make_array();
creds["guacadmin"] = "guacadmin";
url = dir + "/api/tokens";
report = "It was possible to login with the following known default credentials (username:password):\n";
for username in keys( creds ) {
	password = creds[username];
	data = "username=" + username + "&password=" + password;
	req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	headers = http_extract_headers_from_response( data: res );
	body = http_extract_body_from_response( data: res );
	if(!headers || !body){
		continue;
	}
	if(IsMatchRegexp( headers, "Content-Type\\s*:\\s*application/json" ) && ContainsString( body, "\"username\":\"" + username + "\"" )){
		report += "\n" + username + ":" + password;
		VULN = TRUE;
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

