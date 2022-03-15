if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13654" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-0624" );
	script_bugtraq_id( 10746 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Artmedic Kleinanzeigen File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "The file inclusion vulnerability allows a remote attacker to include
  external PHP files as if they were the server's own, this causing the product to execute arbitrary code" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "Artmedic Kleinanzeigen, an email verifying PHP script,
  has been found to contain an external file inclusion vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/kleinanzeigen", "/php/kleinanzeigen", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in make_list( "/index.php",
		 "/index.php3",
		 "/index.php4" ) {
		buf = http_get_cache( item: dir + file, port: port );
		if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || !IsMatchRegexp( buf, "(Freewarescript by artmedic webdesign|Kleinanzeigen von artmedic webdesign|<title>Kleinanzeigen</title>)" )){
			continue;
		}
		url = NASLString( dir, file, "?id=http://xx./" );
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(!buf){
			continue;
		}
		if(ContainsString( buf, "ReadFile(\"http://xx.\")" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

