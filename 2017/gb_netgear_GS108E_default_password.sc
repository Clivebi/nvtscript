CPE_PREFIX = "cpe:/o:netgear:";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108309" );
	script_version( "2021-03-16T10:29:41+0000" );
	script_tag( name: "last_modification", value: "2021-03-16 10:29:41 +0000 (Tue, 16 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-12-05 09:03:31 +0100 (Tue, 05 Dec 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "NETGEAR ProSAFE GS108T Default Password" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_netgear_prosafe_consolidation.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "netgear/prosafe/http/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "summary", value: "The remote NETGEAR ProSAFE GS108E device has the default password 'password'." );
	script_tag( name: "affected", value: "NETGEAR ProSAFE GS108E devices. Other models might be also affected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!get_app_location( cpe: cpe, port: port )){
	exit( 0 );
}
req = http_post_put_req( port: port, url: "/login.cgi", data: "password=password", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
cookie = http_get_cookie_from_header( buf: res, pattern: "(GS[0-9A-Zv]+SID=[^; ]+)" );
if(isnull( cookie )){
	exit( 0 );
}
req = http_get_req( port: port, url: "/switch_info.htm", add_headers: make_array( "Cookie", cookie ) );
res = http_keepalive_send_recv( port: port, data: req );
req = http_get_req( port: port, url: "/logout.cgi", add_headers: make_array( "Cookie", cookie ) );
http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "<title>Switch Information</title>" ) || ContainsString( res, ">Switch Name</td>" ) || ContainsString( res, ">MAC Address</td>" ) || ContainsString( res, ">Firmware Version</td>" ) )){
	security_message( port: port, data: "It was possible to login with the default password 'password'" );
	exit( 0 );
}
exit( 99 );

