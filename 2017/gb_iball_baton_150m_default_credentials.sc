if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113013" );
	script_version( "2020-04-09T12:09:29+0000" );
	script_tag( name: "last_modification", value: "2020-04-09 12:09:29 +0000 (Thu, 09 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-10-11 15:09:33 +0200 (Wed, 11 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "iBall Baton 150M Router Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_goahead_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "embedthis/goahead/detected" );
	script_tag( name: "summary", value: "The iBall Baton 150M Wireless-N Broadband Router uses default credentials, no username and 'admin' as password." );
	script_tag( name: "vuldetect", value: "The script tries to log into the Router's Web Interface using the default credentials." );
	script_tag( name: "impact", value: "Successful exploitation would allow the attacker to gain administrative control over the Router and its settings." );
	script_tag( name: "affected", value: "iBall Baton 150M Wireless-N Broadband Router." );
	script_tag( name: "solution", value: "Change your password to something else." );
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
content = http_get_cache( port: port, item: "/login.asp" );
if(!content || !ContainsString( content, "<title>LOGIN</title>" )){
	exit( 0 );
}
data = "Username=YWRtaW4%3D&Password=YWRtaW4%3D";
accept_header = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive" );
req = http_post_put_req( port: port, url: "/LoginCheck", data: data, add_headers: add_headers, accept_header: accept_header );
res = http_keepalive_send_recv( port: port, data: req );
if( ContainsString( res, "login.asp" ) ){
	exit( 99 );
}
else {
	if(ContainsString( res, "advance.asp" ) && ContainsString( res, "302 Redirect" ) && ContainsString( res, "Set-Cookie: ecos_pw" )){
		report = "It was possible to log in to the Web Interface using the default password 'admin'.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

