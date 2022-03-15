if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805565" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-05-21 11:56:09 +0530 (Thu, 21 May 2015)" );
	script_name( "TORNADO Computer Trading CMS SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with TORNADO CMS
  and is prone to sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able execute sql query or not." );
	script_tag( name: "insight", value: "Flaw exists as the input passed to
  'our_services.php', 'detail.php' and 'products.php' scripts via 'id' parameter
  is not properly sanitized before returning to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Tornado - Content Management System
  2015 Q2" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/131796" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/535465" );
	script_xref( name: "URL", value: "http://www.vulnerability-lab.com/get_content.php?id=1489" );
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
for dir in nasl_make_list_unique( "/", "/tornado", "/cms", "/tornadocms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(IsMatchRegexp( rcvRes, ">Website Designed & Developed By.*>Tornado<" )){
		url = dir + "/products.php?category_id='SQL-INJECTION-TEST";
		if(http_vuln_check( port: http_port, url: url, check_header: FALSE, pattern: "You have an error in your SQL syntax", extra_check: "SQL-INJECTION-TEST" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

