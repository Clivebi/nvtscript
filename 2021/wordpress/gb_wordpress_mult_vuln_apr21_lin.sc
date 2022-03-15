CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145770" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 09:37:06 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 21:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_cve_id( "CVE-2021-29447", "CVE-2021-29450" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Multiple Vulnerabilities (Apr 2021) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "WordPress is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-29447: XXE within the media library

  - CVE-2021-29450: Data exposure within the REST API" );
	script_tag( name: "affected", value: "WordPress versions 4.7 through 5.7." );
	script_tag( name: "solution", value: "Update to version 4.7.20, 4.8.16, 4.9.17, 5.0.12, 5.1.9, 5.2.10, 5.3.7,
  5.4.5, 5.5.4, 5.6.3, 5.7.1 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/" );
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
if(version_in_range( version: version, test_version: "4.7", test_version2: "4.7.19" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.7.20", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.8", test_version2: "4.8.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8.16", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.9", test_version2: "4.9.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.9.17", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0", test_version2: "5.0.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.1", test_version2: "5.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.1.9", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.2", test_version2: "5.2.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.10", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.3", test_version2: "5.3.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.3.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.4", test_version2: "5.4.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.4.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.5", test_version2: "5.5.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.6", test_version2: "5.6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.7", test_version2: "5.7.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.7.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

