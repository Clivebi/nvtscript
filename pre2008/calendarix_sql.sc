if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18410" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2005-1865" );
	script_bugtraq_id( 13825, 13826 );
	script_name( "Calendarix SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.swp-scene.org/?q=node/62" );
	script_tag( name: "impact", value: "Successful exploitation could result in execution of arbitrary
  PHP code on the remote site, a compromise of the application, disclosure or modification of
  data, or may permit an attacker to exploit vulnerabilities in the underlying database implementation." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote host is running Calendarix, a PHP-based calendar system.

  The remote version of this software is prone to a remote file include vulnerability as well as
  multiple cross-site scripting, and SQL injection vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/cal_week.php?op=week&catview=999'";
	if(http_vuln_check( port: port, url: url, pattern: "mysql_num_rows\\(\\): supplied argument is not a valid MySQL result" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

