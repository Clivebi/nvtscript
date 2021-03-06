if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900928" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-28 14:39:11 +0200 (Fri, 28 Aug 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2791" );
	script_bugtraq_id( 35919 );
	script_name( "ProjectButler PHP Remote File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9331" );
	script_xref( name: "URL", value: "http://heapoverflow.com/f0rums/sitemap/t-17452.html" );
	script_tag( name: "impact", value: "Attacker can exploit this issue to execute remote PHP code by
  passing the mailicious URL into the 'offset' parameter." );
	script_tag( name: "affected", value: "ProjectButler version 1.5.0 and prior." );
	script_tag( name: "insight", value: "The input passed into the 'pda_projects.php' script is not
  sufficiently sanitized before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with ProjectButler and is prone to PHP
  Remote File Inclusion vulnerability." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/ProjectButler", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.php";
	rcvRes = http_get_cache( item: url, port: port );
	if(ContainsString( rcvRes, ">ProjectButler<" )){
		url = dir + "/pda/pda_projects.php?offset=ATTACK-STRING";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "ATTACK-STRING" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

