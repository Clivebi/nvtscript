CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808034" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-4029", "CVE-2016-6634", "CVE-2016-6635" );
	script_bugtraq_id( 92400, 92390, 92355 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-05-17 10:26:53 +0530 (Tue, 17 May 2016)" );
	script_name( "WordPress Core Multiple Vulnerabilities May16 (Windows)" );
	script_tag( name: "summary", value: "This host is running WordPress and is prone
  to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper validation of HTTP request for detection of valid IP addresses.

  - An insufficient validation in network setting.

  - A script compression option CSRF." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows
  remote attacker to conduct XSS, CSRF and SSRF bypass attacks." );
	script_tag( name: "affected", value: "WordPress versions prior to 4.5 on Windows." );
	script_tag( name: "solution", value: "Update to WordPress version 4.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/8473" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/8474" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/8475" );
	script_xref( name: "URL", value: "https://codex.wordpress.org/Version_4.5#Security" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "os_detection.sc", "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!wpVer = get_app_version( cpe: CPE, port: wpPort )){
	exit( 0 );
}
if(version_is_less( version: wpVer, test_version: "4.5" )){
	report = report_fixed_ver( installed_version: wpVer, fixed_version: "4.5" );
	security_message( data: report, port: wpPort );
	exit( 0 );
}

