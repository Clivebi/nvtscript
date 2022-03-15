if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113271" );
	script_version( "2020-05-07T12:32:15+0000" );
	script_tag( name: "last_modification", value: "2020-05-07 12:32:15 +0000 (Thu, 07 May 2020)" );
	script_tag( name: "creation_date", value: "2018-09-18 13:12:13 +0200 (Tue, 18 Sep 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "LG Smart IP Device Default Credentials (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_lg_smart_ip_device_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8081 );
	script_mandatory_keys( "lg/smart_ip/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The administrator account on LG Smart IP Devices uses
  the default username 'admin' and the default password 'admin'." );
	script_tag( name: "affected", value: "All LG Smart IP Devices." );
	script_tag( name: "solution", value: "Change the default password." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
CPE = "cpe:/h:lg:smart_ip";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!location = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(location == "/"){
	location = "";
}
url = location + "/httpapi?GetUserLevel&ipAddress=";
auth_header = make_array( "Authorization", "Basic " + base64( str: "admin:admin" ) );
req = http_get_req( port: port, url: url, add_headers: auth_header, accept_header: "*/*" );
res = http_keepalive_send_recv( data: req, port: port );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && !IsMatchRegexp( res, "Error" ) && IsMatchRegexp( res, "UserLevel[ ]*:[ ]*USER_ADMIN" )){
	report = "It was possible to login using the username 'admin' and the password 'admin'.";
	security_message( data: report, port: port );
	url = location + "/httpapi?GetVersion";
	req = http_get_req( port: port, url: url, add_headers: auth_header, accept_header: "*/*" );
	res = http_keepalive_send_recv( data: req, port: port );
	swVer = eregmatch( string: res, pattern: "swVersion[ ]*:[ ]*([0-9.]+)", icase: TRUE );
	hwVer = eregmatch( string: res, pattern: "hwVersion[ ]*:[ ]*([0-9.]+)", icase: TRUE );
	fwVer = eregmatch( string: res, pattern: "fwVersion[ ]*:[ ]*([0-9.]+)", icase: TRUE );
	if(!isnull( swVer[1] )){
		set_kb_item( name: "lg/smart_ip/sw_version", value: swVer[1] );
	}
	if(!isnull( hwVer[1] )){
		set_kb_item( name: "lg/smart_ip/hw_version", value: hwVer[1] );
	}
	if(!isnull( fwVer[1] )){
		set_kb_item( name: "lg/smart_ip/fw_version", value: fwVer[1] );
	}
	exit( 0 );
}
exit( 99 );

