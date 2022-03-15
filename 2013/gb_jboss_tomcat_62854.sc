if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103811" );
	script_bugtraq_id( 57552, 62854 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-0874", "CVE-2013-4810" );
	script_name( "Apache Tomcat/JBoss EJBInvokerServlet / JMXInvokerServlet (RMI over HTTP) Marshalled Object Remote Code Execution" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-10-15 10:27:36 +0200 (Tue, 15 Oct 2013)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.zerodayinitiative.com/advisories/ZDI-13-229/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57552" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62854" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/28713/" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/30211" );
	script_tag( name: "impact", value: "Successfully exploiting these issues may allow an attacker to execute
  arbitrary code within the context of the affected application. Failed
  exploit attempts may result in a denial-of-service condition." );
	script_tag( name: "vuldetect", value: "Determine if the EJBInvokerServlet and/or JMXInvokerServlet is accessible without authentication." );
	script_tag( name: "insight", value: "The specific flaw exists within the exposed EJBInvokerServlet and JMXInvokerServlet. An unauthenticated
  attacker can post a marshalled object allowing them to install an arbitrary application on the target server." );
	script_tag( name: "solution", value: "Ask the Vendor for an update and enable authentication for the mentioned servlets." );
	script_tag( name: "summary", value: "Apache Tomcat/JBoss Application Server is prone to multiple remote code-
  execution vulnerabilities." );
	script_tag( name: "affected", value: "Apache Tomcat/JBoss Application Server providing access to the EJBInvokerServlet and/or JMXInvokerServlet
  without prior authentication." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 9200 );
report = "The following Servlets are accessible without authentication which indicates that a RCE attack can be executed:\n";
for file in make_list( "/EJBInvokerServlet",
	 "/JMXInvokerServlet" ) {
	url = "/invoker" + file;
	req = http_get( item: url, port: port );
	buf = http_send_recv( port: port, data: req );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && !ContainsString( buf, "404" ) && ContainsString( buf, "org.jboss.invocation.MarshalledValue" ) && ContainsString( buf, "x-java-serialized-object" ) && !ContainsString( buf, "WWW-Authenticate" )){
		report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		VULN = TRUE;
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

