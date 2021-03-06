if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113240" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-08-01 12:07:22 +0200 (Wed, 01 Aug 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Web Remote Viewer Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_web_remote_viewer_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "web_remote_viewer/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Web Remote Viewer has
  the default username 'ADMIN' with the default password '1234'." );
	script_tag( name: "vuldetect", value: "Tries to login using the default username and password." );
	script_tag( name: "affected", value: "All IP Cameras running Web Remote Viewer." );
	script_tag( name: "solution", value: "Change the password of the 'ADMIN' account." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
CPE = "cpe:/a:dvr:web_remote_viewer";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!path = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(path == "/"){
	path = "";
}
url = path + "/html/live.htm";
username = "ADMIN";
password = "1234";
auth_header = make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) );
req = http_get_req( port: port, url: url, add_headers: auth_header );
buf = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( buf, "<div id=\"lang_[Cc]hannel[Nn]o\">[Cc]hannel [Nn]o[.]</div>" )){
	report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

