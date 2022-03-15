CPE = "cpe:/a:ntop:ntopng";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112078" );
	script_version( "2021-05-10T06:48:45+0000" );
	script_tag( name: "last_modification", value: "2021-05-10 06:48:45 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2017-10-11 10:51:21 +0200 (Wed, 11 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "ntopng Default Admin Credentials Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_ntopng_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 3000 );
	script_mandatory_keys( "ntopng/http/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "ntopng is prone to a default account authentication bypass
  vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information." );
	script_tag( name: "vuldetect", value: "This script tries to login with default credentials." );
	script_tag( name: "solution", value: "Change the password." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
data = NASLString( "user=admin&password=admin&referer=" + host + "%2Fauthorize.html" );
req = http_post_put_req( port: port, url: "/authorize.html", data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ), accept_headers: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" );
res = http_keepalive_send_recv( port: port, data: req );
cookie = eregmatch( pattern: "Set-Cookie: session=([0-9a-zA-Z]+)", string: res );
if(isnull( cookie[1] )){
	exit( 0 );
}
req = http_get_req( port: port, url: "/", add_headers: make_array( "Cookie", "session=" + cookie[1] + "; user=admin" ), accept_headers: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "<li><a href=\"/lua/logout.lua\"><i class=\"fa fa-sign-out\"></i> Logout admin</a></li>" ) && ContainsString( res, "<a href=\"/lua/admin/users.lua\"><span class=\"label label-primary\">admin</span></a>" )){
	security_message( port: port, data: "It was possible to login with the following default credentials Username: \"admin\" & Password: \"admin\"" );
	exit( 0 );
}
exit( 99 );

