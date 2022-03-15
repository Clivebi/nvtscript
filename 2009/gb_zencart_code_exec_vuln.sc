if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800820" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2254", "CVE-2009-2255" );
	script_bugtraq_id( 35467, 35468 );
	script_name( "Zen Cart Arbitrary Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35550" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9004" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9005" );
	script_xref( name: "URL", value: "http://www.zen-cart.com/forum/showthread.php?t=130161" );
	script_xref( name: "URL", value: "http://www.zen-cart.com/forum/attachment.php?attachmentid=5965" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attacker to execute SQL commands
  or arbitrary code by uploading a .php file, and compromise the application,
  or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Zen Cart version 1.3.8a and prior." );
	script_tag( name: "insight", value: "- Error in admin/sqlpatch.php file due to lack of sanitisation of the input
  query string passed into the 'query_string' parameter in an execute action in conjunction with a PATH_INFO of
  password_forgotten.php file.

  - Access to admin/record_company.php is not restricted and can be exploited via the record_company_image parameter
  in conjunction with a PATH_INFO of password_forgotten.php, then accessing this file via a direct request to
  the file in images/." );
	script_tag( name: "solution", value: "Apply the security patch from the references." );
	script_tag( name: "summary", value: "The host is running Zen Cart and is prone to Arbitrary Code
  Execution vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
zencartPort = http_get_port( default: 80 );
if(!http_can_host_php( port: zencartPort )){
	exit( 0 );
}
host = http_host_name( port: zencartPort );
for dir in nasl_make_list_unique( "/", "/zencart", "/cart", http_cgi_dirs( port: zencartPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/admin/login.php", port: zencartPort );
	if(IsMatchRegexp( rcvRes, "<title>Zen Cart!</title>" ) && IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" )){
		postdata = NASLString( "query_string=;" );
		req = NASLString( "POST ", dir, "/admin/sqlpatch.php/password_forgotten.php?action=execute HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
		res = http_keepalive_send_recv( port: zencartPort, data: req, bodyonly: TRUE );
		if(ContainsString( res, "1 statements processed" )){
			security_message( port: zencartPort );
			exit( 0 );
		}
	}
}
exit( 99 );

