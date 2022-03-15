CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11042" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 5194 );
	script_name( "Apache Tomcat DOS Device Name XSS" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "cross_site_scripting.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/tomcat/http/detected" );
	script_xref( name: "URL", value: "http://www.westpoint.ltd.uk/advisories/wp-02-0008.txt" );
	script_tag( name: "solution", value: "Upgrade to Apache Tomcat v4.1.3 beta or later." );
	script_tag( name: "summary", value: "The remote Apache Tomcat web server is vulnerable to a cross site scripting
  issue." );
	script_tag( name: "insight", value: "By making requests for DOS Device names it is possible to cause
  Tomcat to throw an exception, allowing XSS attacks, e.g:

  tomcat-server/COM2.IMG%20src='Javascript:alert(document.domain)'

  (angle brackets omitted)

  The exception also reveals the physical path of the Tomcat installation." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
url = "/COM2.<IMG%20SRC='JavaScript:alert(document.domain)'>";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
confirmed = NASLString( "JavaScript:alert(document.domain)" );
confirmed_too = NASLString( "java.io.FileNotFoundException" );
if(( ContainsString( res, confirmed ) ) && ( ContainsString( res, confirmed_too ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

