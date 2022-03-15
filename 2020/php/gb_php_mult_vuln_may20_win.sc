CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143914" );
	script_version( "2021-07-08T11:00:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 11:00:45 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-15 03:04:21 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_cve_id( "CVE-2019-11048" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHP < 7.2.31, 7.3 < 7.3.18, 7.4 < 7.4.6 Multiple DoS Vulnerabilities - May20 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "PHP is prone to two Denial-of-Service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following flaws exist:

  - Long filenames cause OOM and temp files to not be cleaned

  - Long variables in multipart/form-data cause OOM and temp files are not cleaned

  leading to a Denial-of-Service condition (CVE-2019-11048)." );
	script_tag( name: "affected", value: "PHP versions prior 7.2.31, 7.3 prior 7.3.18 and 7.4 prior to 7.4.6." );
	script_tag( name: "solution", value: "Update to version 7.2.31, 7.3.18, 7.4.6 or later." );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.2.31" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.3.18" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.4.6" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=78875" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=78876" );
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
if(version_is_less( version: version, test_version: "7.2.31" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.2.31", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.3.0", test_version2: "7.3.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.3.18", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.4.0", test_version2: "7.4.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.4.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

