if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112096" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-26 13:43:51 +0200 (Thu, 26 Oct 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-06 12:55:00 +0000 (Tue, 06 Apr 2021)" );
	script_cve_id( "CVE-2015-5532" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Paid Memberships Pro Plugin Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/paid-memberships-pro/detected" );
	script_tag( name: "summary", value: "Multiple cross-site scripting (XSS) vulnerabilities in the Paid Memberships Pro (PMPro) plugin for WordPress
      allow remote attackers to inject arbitrary web script or HTML via the (1) s parameter to membershiplevels.php, (2) memberslist.php,
      or (3) orders.php in adminpages/ or the (4) edit parameter to adminpages/membershiplevels.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Paid Memberships Pro plugin before 1.8.4.3." );
	script_tag( name: "solution", value: "Update to version 1.8.4.3 or later." );
	script_xref( name: "URL", value: "http://www.paidmembershipspro.com/2015/07/pmpro-updates-1-8-4-3-and-1-8-4-4/" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/paid-memberships-pro/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:strangerstudios:paid-memberships-pro";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.8.4.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.4.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

