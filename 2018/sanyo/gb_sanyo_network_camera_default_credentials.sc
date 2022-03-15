if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114021" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-08-15 14:08:31 +0200 (Wed, 15 Aug 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Sanyo Network Camera Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_sanyo_network_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sanyo/network_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Sanyo network cameras use the default credentials admin:admin." );
	script_tag( name: "vuldetect", value: "Tries to login using default credentials." );
	script_tag( name: "affected", value: "All Sanyo cameras using this web interface." );
	script_tag( name: "solution", value: "Change the default password." );
	script_xref( name: "URL", value: "https://ipvm.com/reports/ip-cameras-default-passwords-directory" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
CPE = "cpe:/h:sanyo:network_camera";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
username = "admin";
password = "admin";
auth_header = make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) );
req = http_get_req( port: port, url: "/", add_headers: auth_header );
res = http_keepalive_send_recv( port: port, data: req );
if(( ContainsString( res, "<IMG src=\"../img/SANYO_lan.gif\"></TD>" ) && ContainsString( res, "<TITLE>SANYO  NETWORK CAMERA</TITLE>" ) ) || ContainsString( res, "top.window.location.replace(\"/cgi-bin/lang.cgi\");" )){
	report = "It was possible to login using the username \"" + username + "\" and the password \"" + password + "\".";
	session = eregmatch( pattern: "NOBSESS=([0-9a-zA-z]+)", string: res );
	sessionCookie = session[0];
	versionUrl = "/cgi-bin/option.cgi";
	if( sessionCookie ){
		req = http_get_req( port: port, url: versionUrl, add_headers: make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) + "=", "Cookie", sessionCookie ) );
	}
	else {
		req = http_get_req( port: port, url: versionUrl, add_headers: make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) + "=" ) );
	}
	res = http_keepalive_send_recv( port: port, data: req );
	mainVer = eregmatch( pattern: "(CAM)?\\s*MAIN\\s*Ver.\\s*([0-9.-]+)", string: res );
	subVer = eregmatch( pattern: "(CAM)?\\s*SUB\\s*Ver.\\s*([0-9.-]+)", string: res );
	if(mainVer[2]){
		set_kb_item( name: "sanyo/network_camera/main/version", value: mainVer[2] );
	}
	if(subVer[2]){
		set_kb_item( name: "sanyo/network_camera/sub/version", value: subVer[2] );
	}
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

