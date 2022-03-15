if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114087" );
	script_version( "2020-04-12T06:48:30+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2020-04-12 06:48:30 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2019-03-20 14:57:35 +0100 (Wed, 20 Mar 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Intellio Visus Default Credentials" );
	script_dependencies( "gb_intellio_visus_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "intellio/visus/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://technodocbox.com/Cameras_and_Camcorders/67505238-Firmware-version-3-2-0.html" );
	script_tag( name: "summary", value: "The remote installation of Intellio Visus is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Intellio Visus is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Intellio Visus' web interface is possible." );
	script_tag( name: "solution", value: "Change the passwords for user and admin access." );
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
CPE = "cpe:/a:intellio:visus";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin" );
url = "/login";
req = http_get_req( port: port, url: url );
res = http_keepalive_send_recv( port: port, data: req );
if( ContainsString( res, "\"BadRequestException\"" ) ) {
	hostType = "POST_login";
}
else {
	hostType = "GET_authorize";
}
for cred in keys( creds ) {
	if( hostType == "GET_authorize" ){
		url = "/authorize?user=" + cred + "&password=" + creds[cred];
		req = http_get_req( port: port, url: url );
	}
	else {
		if(hostType == "POST_login"){
			data = "{\"User\":\"" + cred + "\",\"Password\":\"" + creds[cred] + "\"}";
			auth = "user=" + cred + "; password=" + creds[cred];
			req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Cookie", auth ) );
		}
	}
	res = http_keepalive_send_recv( port: port, data: req );
	if(( IsMatchRegexp( res, "Set-Cookie:\\s*session=" ) && IsMatchRegexp( res, "Set-Cookie:\\s*user=" ) ) || IsMatchRegexp( res, "\"sid\"\\s*:\\s*\"[^\"]+\"" )){
		VULN = TRUE;
		report += "\n" + cred + ":" + creds[cred];
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials (username:password):\n" + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

