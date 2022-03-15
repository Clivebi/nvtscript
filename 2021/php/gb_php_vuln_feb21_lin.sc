CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145323" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-05 03:42:17 +0000 (Fri, 05 Feb 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 15:15:00 +0000 (Thu, 15 Jul 2021)" );
	script_cve_id( "CVE-2021-21702" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHP < 7.3.27, 7.4 < 7.4.15, 8.0 < 8.0.2 NULL Deference Vulnerability - February21 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "PHP is prone to a NULL dereference vulnerability in the SoapClient." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PHP versions prior to 7.3.27, 7.4 prior to 7.4.15 and 8.0 prior to 8.0.2." );
	script_tag( name: "solution", value: "Update to version 7.3.27, 7.4.15, 8.0.2 or later." );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.3.27" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.4.15" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-8.php#8.0.2" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "7.3.27" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.3.27", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.4.0", test_version2: "7.4.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.4.15", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0.0", test_version2: "8.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

