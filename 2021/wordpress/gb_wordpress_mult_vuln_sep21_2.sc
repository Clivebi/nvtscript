CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117701" );
	script_version( "2021-09-29T11:08:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 11:08:31 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-28 05:01:30 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-24 14:00:00 +0000 (Fri, 24 Sep 2021)" );
	script_cve_id( "CVE-2021-39202", "CVE-2021-39203" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress 5.8 beta Multiple Vulnerabilities (Sep 2021)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "WordPress is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-39202: Stored Cross-Site Scripting (XSS) vulnerability in widget editor

  - CVE-2021-39203: Private data disclosure/privilege escalation through the block editor" );
	script_tag( name: "affected", value: "WordPress 5.8 beta during the testing period." );
	script_tag( name: "solution", value: "Update to the final 5.8 release or later." );
	script_xref( name: "URL", value: "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fr6h-3855-j297" );
	script_xref( name: "URL", value: "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-qxvw-qxm9-qvg6" );
	exit( 0 );
}
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
if(version_is_equal( version: version, test_version: "5.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.8 final", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

