CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808252" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-5098", "CVE-2016-5097" );
	script_bugtraq_id( 90878, 90881 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-08-04 13:01:28 +0530 (Thu, 04 Aug 2016)" );
	script_name( "phpMyAdmin Multiple Information Disclosure Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2016-15" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2016-14" );
	script_xref( name: "URL", value: "https://github.com/phpmyadmin/phpmyadmin/commit/d2dc9481d2af25b035778c67eaf0bfd2d2c59dd8" );
	script_tag( name: "summary", value: "This host is installed with phpMyAdmin
  and is prone to multiple information disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to obtain sensitive information or not." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A directory traversal vulnerability in 'libraries/error_report.lib.php'
    script.

  - The tokens are placed in query strings and does not arrange for them to be
    stripped before external navigation." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to determine the existence of arbitrary files by triggering an error
  and also to obtain sensitive information by reading (1) HTTP requests or (2)
  server logs." );
	script_tag( name: "affected", value: "phpMyAdmin versions before 4.6.2" );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin version 4.6.2 or
  later." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/libraries/error_report.lib.php";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "Fatal error.*libraries/Util.class.php' \\(include_path=.*/libraries/error_report.lib.php" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

