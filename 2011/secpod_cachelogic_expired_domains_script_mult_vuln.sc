if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902449" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Cachelogic Expired Domains Script Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17428/" );
	script_xref( name: "URL", value: "http://itsecuritysolutions.org/2011-03-24_Cachelogic_Expired_Domains_Script_1.0_multiple_security_vulnerabilities/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in 'stats.php' when handling the 'name' and 'ext' parameters.

  - A full path disclosure vulnerability in 'index.php' when handling various
    parameters.

  - A SQL injection vulnerability in 'index.php' when handling 'ncharacter' parameter." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is running cahelogic expired domains script and is prone
  multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and manipulate SQL queries by injecting arbitrary SQL code
  in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Cachelogic Expired Domains Script version 1.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://code.google.com/p/eventh/downloads/list" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
cedmPort = http_get_port( default: 80 );
if(!http_can_host_php( port: cedmPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/demo", "/cedm", http_cgi_dirs( port: cedmPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: cedmPort );
	if(ContainsString( rcvRes, ">Cachelogic Expired and Deleted Domain" )){
		sndReq = http_get( item: NASLString( dir, "/stats.php?ext='><script>alert" + "('XSS-TEST')</script><p+'" ), port: cedmPort );
		rcvRes = http_keepalive_send_recv( port: cedmPort, data: sndReq );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "><script>alert('XSS-TEST')</script>" )){
			security_message( port: cedmPort );
			exit( 0 );
		}
	}
}
exit( 99 );

