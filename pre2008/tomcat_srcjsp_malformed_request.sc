CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12123" );
	script_version( "2021-01-15T14:11:28+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 14:11:28 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2000-1210" );
	script_bugtraq_id( 4876 );
	script_name( "Apache Tomcat source.jsp malformed request information disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 David Kyger" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/tomcat/http/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/4876" );
	script_tag( name: "solution", value: "Remove default files from the web server." );
	script_tag( name: "summary", value: "The source.jsp file, distributed with Apache Tomcat server, will
  disclose information when passed a malformed request." );
	script_tag( name: "impact", value: "As a result, information such as the web root path and directory
  listings could be obtained.

  Examples:

  http://example.com/examples/jsp/source.jsp?? - reveals the web root

  http://example.com/examples/jsp/source.jsp?/jsp/ - reveals the contents of the jsp directory" );
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
for url in make_list( "/examples/jsp/source.jsp??",
	 "/examples/jsp/source.jsp?/jsp/" ) {
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "Directory Listing" ) && ContainsString( buf, "file" )){
		report = http_report_vuln_url( port: port, url: url );
		report += "\n\nThe following information was obtained via a malformed request to the web server:\n\n" + buf;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

