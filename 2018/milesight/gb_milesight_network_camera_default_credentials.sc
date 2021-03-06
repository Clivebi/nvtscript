if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113231" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-07-17 16:09:00 +0200 (Tue, 17 Jul 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Milesight Network Cameras Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_milesight_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "milesight/network_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Milesight Network Cameras use the default credentials admin:ms1234." );
	script_tag( name: "vuldetect", value: "Tries to login using default credentials." );
	script_tag( name: "affected", value: "All Milesight Network Cameras." );
	script_tag( name: "solution", value: "Change the default password." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
CPE = "cpe:/h:milesight:network_camera";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
username = "admin";
password = "ms1234";
password_hash = hexstr( MD5( password ) );
url = "/vb.htm?checkpassword=0:" + username + ":" + password_hash;
buf = http_get_cache( port: port, item: url );
if(IsMatchRegexp( buf, "OK[ ]*checkpassword" )){
	report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

