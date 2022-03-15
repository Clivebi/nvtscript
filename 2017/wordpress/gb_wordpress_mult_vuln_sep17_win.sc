CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811783" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-14723" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-10 02:29:00 +0000 (Fri, 10 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-09-21 12:01:02 +0530 (Thu, 21 Sep 2017)" );
	script_name( "WordPress Multiple Vulnerabilities - Sep 2017 (Windows)" );
	script_tag( name: "summary", value: "WordPress is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - '$wpdb->prepare' can create unexpected and unsafe queries.

  - An unspecified error in the customizer.

  - Multiple other unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct cross site scripting, SQL injection, directory traversal
  and open redirect attacks." );
	script_tag( name: "affected", value: "WordPress versions 4.8.1 and earlier" );
	script_tag( name: "solution", value: "Update to WordPress version 4.8.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://codex.wordpress.org/Version_4.8.2" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "os_detection.sc", "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wordPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: wordPort )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "4.8.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.8.2" );
	security_message( data: report, port: wordPort );
	exit( 0 );
}
exit( 0 );

