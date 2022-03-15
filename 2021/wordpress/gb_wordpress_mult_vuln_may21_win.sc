CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145945" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-14 07:01:17 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 15:17:00 +0000 (Mon, 14 Jun 2021)" );
	script_cve_id( "CVE-2018-19296", "CVE-2020-36326" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Multiple Vulnerabilities (May 2021) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "WordPress is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2018-19296: PHPMailer is vulnerable to an object injection attack.

  - CVE-2021-29450: PHPMailer allows object injection through Phar Deserialization via addAttachment
    with a UNC pathname." );
	script_tag( name: "affected", value: "WordPress versions 3.7 through 5.7." );
	script_tag( name: "solution", value: "Update to version 3.7.36, 3.8.36, 3.9.34, 4.0.33, 4.1.33, 4.2.30,
  4.3.26, 4.4.25, 4.5.24, 4.6.21, 4.7.21, 4.8.17, 4.9.18, 5.0.13, 5.1.10, 5.2.11, 5.3.8, 5.4.6, 5.5.5,
  5.6.4, 5.7.2 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/" );
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
if(version_in_range( version: version, test_version: "3.7", test_version2: "3.7.35" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.7.36", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.8", test_version2: "3.8.35" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.8.36", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.9", test_version2: "3.9.33" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.34", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0", test_version2: "4.0.32" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.33", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.1", test_version2: "4.1.32" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.33", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.2", test_version2: "4.2.29" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.30", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.3", test_version2: "4.3.25" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.26", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.4", test_version2: "4.4.24" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.4.25", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.5", test_version2: "4.5.23" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.24", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.6", test_version2: "4.6.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.6.21", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.7", test_version2: "4.7.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.7.21", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.8", test_version2: "4.8.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8.17", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.9", test_version2: "4.9.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.9.18", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0", test_version2: "5.0.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.13", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.1", test_version2: "5.1.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.1.10", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.2", test_version2: "5.2.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.11", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.3", test_version2: "5.3.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.3.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.4", test_version2: "5.4.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.4.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.5", test_version2: "5.5.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.6", test_version2: "5.6.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.7", test_version2: "5.7.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.7.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

