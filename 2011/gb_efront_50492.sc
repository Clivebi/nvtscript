CPE = "cpe:/a:efrontlearning:efront";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103328" );
	script_bugtraq_id( 50492 );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "eFront Multiple Cross Site Scripting and SQL Injection Vulnerabilities" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-11-03 08:00:00 +0100 (Thu, 03 Nov 2011)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_efront_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "efront/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50492" );
	script_xref( name: "URL", value: "http://www.efrontlearning.net/" );
	script_xref( name: "URL", value: "https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_efront.html" );
	script_tag( name: "impact", value: "Exploiting these vulnerabilities could allow an attacker to steal
  cookie-based authentication credentials, compromise the application, access or modify data, or
  exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "eFront 3.6.10 build 11944 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "eFront is prone to multiple cross-site scripting and SQL-injection
  vulnerabilities because the software fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php/'><script>alert(/vt-xss-test/);</script>";
if(http_vuln_check( port: port, url: url, pattern: "><script>alert\\(/vt-xss-test/\\);</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

