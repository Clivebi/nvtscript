if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117075" );
	script_version( "2020-12-14T14:31:19+0000" );
	script_tag( name: "last_modification", value: "2020-12-14 14:31:19 +0000 (Mon, 14 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-11 13:44:24 +0000 (Fri, 11 Dec 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "D-Link DSR Devices Default Login (HTTP)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "gb_dlink_dsr_http_detect.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "Host/is_d-link_dsr_device" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "summary", value: "The remote D-Link DSR device is using known default credentials." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "affected", value: "All D-Link DSR devices with default credentials." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
CPE_PREFIX = "cpe:/o:d-link";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("url_func.inc.sc");
require("misc_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
username = "admin";
password = "admin";
url = "/scgi-bin/platform.cgi";
ua = http_get_user_agent();
ua = urlencode( str: ua );
data = "thispage=index.html&Users.UserName=" + username + "&Users.Password=" + password + "&button.login.Users.dashboard=Login&Login.userAgent=" + ua + "&loggedInStatus=";
req = http_post_put_req( port: port, url: url, data: data, referer_url: url, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(( ContainsString( res, "<p>User Already Logged In</p>" ) && ContainsString( res, "If you want to close the other session, please click on" ) ) || ( ( ContainsString( res, "Logged in as:" ) && ContainsString( res, "admin" ) ) || ( ContainsString( res, "class=\"btnLogout\"" ) && ( ContainsString( res, "?page=lanSettings.html" ) || ContainsString( res, "?page=deviceInfo.html" ) ) ) )){
	report = "It was possible to login with username '" + username + "' and password '" + password + "'.";
	security_message( port: port, data: report );
	exit( 0 );
}
data = "thispage=index.htm&Users.UserName=" + username + "&Users.Password=" + password + "&button.login.Users.deviceStatus=Login&Login.userAgent=" + ua;
req = http_post_put_req( port: port, url: url, data: data, referer_url: url, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(( ContainsString( res, ">User already logged in</td>" ) && ContainsString( res, "If you want to close the other session, please click on" ) ) || ( ContainsString( res, "<td class=\"logout\"><a href=\"?page=index.htm\">Logout</a></td>" ) || ContainsString( res, "<a href=\"?page=wanWizard.htm\">SETUP</a></li>" ) || ContainsString( res, "<a href=\"?page=adminSettings.htm\">TOOLS</a></li>" ) )){
	report = "It was possible to login with username '" + username + "' and password '" + password + "'.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

