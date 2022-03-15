CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111014" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-04-15 07:00:00 +0100 (Wed, 15 Apr 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2007-1355" );
	script_bugtraq_id( 24476 );
	script_name( "Apache Tomcat JSP Example Web Applications Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/tomcat/http/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/24476/" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-6.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-5.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-4.html" );
	script_tag( name: "impact", value: "Exploiting this vulnerability may allow an attacker to perform cross-site scripting attacks on unsuspecting users
  in the context of the affected website. As a result, the attacker may be able to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Apache Tomcat version 4.0.1 to 4.0.6, 4.1.0 to 4.1.36, 5.0.0 to 5.0.30, 5.5.0 to 5.5.23 and 6.0.0 to 6.0.10" );
	script_tag( name: "solution", value: "Update your Apache Tomcat to a non-affected version." );
	script_tag( name: "summary", value: "This host is running Apache Tomcat and is prone to Cross Site Scripting
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/jsp-examples/snp/snoop.jsp;test<script>alert('attack');</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('attack'\\);</script>", extra_check: "test", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

