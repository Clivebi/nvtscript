if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112133" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2017-11-22 11:46:00 +0100 (Wed, 22 Nov 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Lantronix Devices Unprotected Web Access" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_lantronix_device_version.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "lantronix_device/http/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The Lantronix UDS1100 Device Server web interface is accessible via an unprotected HTTP connection." );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to configure and control the device." );
	script_tag( name: "solution", value: "Ensure that the Lantronix web access is protected via strong login credentials." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
if(!port = get_kb_item( "lantronix_device/http/port" )){
	exit( 0 );
}
url = "/secure/welcome.htm";
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 401" )){
	exit( 0 );
}
userpass = "root:";
userpass64 = base64( str: userpass );
added_headers = make_array( "Authorization", "Basic " + userpass64 );
req = http_get_req( port: port, url: "/secure/menu.htm", add_headers: added_headers, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
res = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Device Server Home Page" ) && ContainsString( res, "Configure IP address and hostname" ) && ContainsString( res, "Configure global server settings" ) && ContainsString( res, "Apply Settings" ) && ContainsString( res, "Apply Defaults" )){
	report = "The Lantronix Device web-manager configuration could be accessed with any username and an empty password.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

