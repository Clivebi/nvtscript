CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807078" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_cve_id( "CVE-2016-2044", "CVE-2016-2045" );
	script_bugtraq_id( 82104, 82100 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-08-17 19:37:00 +0000 (Wed, 17 Aug 2016)" );
	script_tag( name: "creation_date", value: "2016-02-22 19:19:14 +0530 (Mon, 22 Feb 2016)" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "phpMyAdmin Multiple Vulnerabilities -02 Feb16" );
	script_tag( name: "summary", value: "This host is installed with phpMyAdmin
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to obtain sensitive information or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - recommended setting of the PHP configuration directive display_errors is
    set to on, which is against the recommendations given in the PHP manual
    for a production server.

  - Insufficient validation of user supplied input via SQL query in the
    SQL editor" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain sensitive information about the server and to inject
  arbitrary web script or HTML." );
	script_tag( name: "affected", value: "phpMyAdmin versions 4.5.x before 4.5.4" );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin version 4.5.4 or
  or later or apply the patch from the linked references." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2016-9" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2016-8" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/libraries/sql-parser/autoload.php";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "Fatal error.*autoload.php" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}

