CPE = "cpe:/a:phpmyfaq:phpmyfaq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100829" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2010-09-29 12:56:18 +0200 (Wed, 29 Sep 2010)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 43560 );
	script_name( "phpMyFAQ 'index.php' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43560" );
	script_xref( name: "URL", value: "http://www.phpmyfaq.de/advisory_2010-09-28.php" );
	script_xref( name: "URL", value: "http://www.phpmyfaq.de/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "phpmyfaq_detect.sc" );
	script_mandatory_keys( "phpmyfaq/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "phpMyFAQ is prone to a cross-site scripting vulnerability because it fails
  to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to phpMyFAQ 2.6.9 are vulnerable." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php/%22%3E%3Cscript%3Ealert(%27vt-xss-test%27)%3C/script%3E";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('vt-xss-test'\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

