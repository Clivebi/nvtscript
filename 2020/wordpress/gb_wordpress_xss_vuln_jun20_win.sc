CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144105" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-15 04:37:58 +0000 (Mon, 15 Jun 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-01 15:15:00 +0000 (Wed, 01 Jul 2020)" );
	script_cve_id( "CVE-2020-4046" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress XSS Vulnerability - June20 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "WordPress is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Users with low privileges (like contributors and authors) can use the embed
  block in a certain way to inject unfiltered HTML in the block editor. When affected posts are viewed by a
  higher privileged user, this could lead to script execution in the editor/wp-admin." );
	script_tag( name: "affected", value: "WordPress versions 5.1 - 5.4.1." );
	script_tag( name: "solution", value: "Update to version 5.1.6, 5.2.7, 5.3.4, 5.4.2 or later." );
	script_xref( name: "URL", value: "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rpwf-hrh2-39jf" );
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
if(version_in_range( version: version, test_version: "5.1", test_version2: "5.1.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.1.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.2", test_version2: "5.2.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.3", test_version2: "5.3.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.3.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.4", test_version2: "5.4.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.4.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
