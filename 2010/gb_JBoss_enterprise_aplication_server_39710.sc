if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100610" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)" );
	script_bugtraq_id( 39710 );
	script_cve_id( "CVE-2010-0738", "CVE-2010-1428", "CVE-2010-1429" );
	script_name( "JBoss Enterprise Application Platform Multiple Vulnerabilities" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "JBoss_enterprise_aplication_server_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "jboss/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39710" );
	script_tag( name: "impact", value: "An attacker can exploit these issues to bypass certain security
  restrictions to obtain sensitive information or gain unauthorized access to the application." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "JBoss Enterprise Application Platform is prone to multiple
  vulnerabilities, including an information-disclosure issue and
  multiple authentication-bypass issues." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_kb_item( "jboss/port" )){
	exit( 0 );
}
url = "/jmx-console";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf || IsMatchRegexp( buf, "^HTTP/1\\.[01] [23]00" )){
	exit( 0 );
}
url = "/jmx-console/checkJNDI.jsp";
host = http_host_name( port: port );
req = NASLString( "PUT ", url, " HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n", "\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "JNDI Check</title>" ) && ContainsString( res, "JNDI Checking for host" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

