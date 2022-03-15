if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802404" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_cve_id( "CVE-2010-5020" );
	script_bugtraq_id( 41014 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-11-14 13:46:57 +0530 (Mon, 14 Nov 2011)" );
	script_name( "NetArt Media iBoutique 'page' SQL Injection and XSS Vulnerabilities" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/6444" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31871" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/13945/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running NetArt Media iBoutique and is prone to
  multiple SQL injection and cross-site scripting vulnerabilities." );
	script_tag( name: "insight", value: "Multiple flaws are due to an:

  - Input passed to the 'cat' and 'key'  parameter in index.php (when 'mod'
  is set to 'products') is not properly sanitised before being used in a SQL query.

  - Input passed to the 'page' parameter in index.php is not properly sanitised
  before being used in a SQL query.

  This can further be exploited to conduct cross-site scripting attacks
  via SQL error messages." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to conduct SQL
  injection and cross-site scripting attacks." );
	script_tag( name: "affected", value: "NetArt Media iBoutique version 4.0" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
ibPort = http_get_port( default: 80 );
if(!http_can_host_php( port: ibPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/iboutique", http_cgi_dirs( port: ibPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: ibPort );
	if(ContainsString( rcvRes, ">Why iBoutique?</" )){
		url = NASLString( dir, "/index.php?page='" );
		if(http_vuln_check( port: ibPort, url: url, pattern: "You have an error" + " in your SQL syntax;", check_header: TRUE )){
			security_message( port: ibPort );
			exit( 0 );
		}
	}
}
exit( 99 );

