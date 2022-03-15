if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113233" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-07-19 10:04:40 +0200 (Thu, 19 Jul 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Mobotix Webcam Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_mobotix_webcam_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "mobotix/webcam/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Mobotix Webcams use the default credentials admin:meinsm." );
	script_tag( name: "vuldetect", value: "Tries to login using default credentials." );
	script_tag( name: "affected", value: "All Mobotix Webcams." );
	script_tag( name: "solution", value: "Change the default password." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
CPE = "cpe:/h:mobotix:webcam";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
username = "admin";
password = "meinsm";
auth_header = make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) );
req = http_get_req( port: port, url: "/", add_headers: auth_header );
buf = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( buf, "Live <\\/TITLE>" ) || ( ContainsString( buf, "params[\'size\']" ) && ContainsString( buf, "params[\'camera\']" ) && ContainsString( buf, "params[\'quality\']" ) )){
	report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

