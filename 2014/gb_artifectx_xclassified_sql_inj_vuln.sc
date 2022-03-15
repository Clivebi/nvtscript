if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804684" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-4741" );
	script_bugtraq_id( 68438 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-07-21 11:57:35 +0530 (Mon, 21 Jul 2014)" );
	script_name( "Artifectx xClassified 'catid' SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Artifectx xClassified and is prone to sql injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it is able to execute
  sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to the 'ads.php' script not properly sanitizing user-supplied input
  to the 'catid' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to manipulate SQL queries in the
  backend database allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Artifectx XClassified version 1.2" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127370" );
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
for dir in nasl_make_list_unique( "/", "/ads", "/classifieds", "/artifectx", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(ContainsString( rcvRes, ">xClassified Web" ) && ContainsString( rcvRes, "artifectx" )){
		url = dir + "/ads.php?catid=1'SQL-Injection-Test";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "SQL-Injection-Test", extra_check: make_list( "Artifectx",
			 ">Login<" ) )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

