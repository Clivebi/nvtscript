CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146339" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-21 05:11:56 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-29 16:37:00 +0000 (Thu, 29 Jul 2021)" );
	script_cve_id( "CVE-2021-32767" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TYPO3 Information Disclosure Vulnerability (TYPO3-CORE-SA-2021-012)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_tag( name: "summary", value: "TYPO3 is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It has been discovered that user credentials have been logged
  as plaintext when explicitly using log level debug, which is not the default configuration." );
	script_tag( name: "affected", value: "TYPO3 version 7.0.0 through 7.6.51 ELTS, 8.0.0 through
  8.7.40 ELTS, 9.0.0 through 9.5.27, 10.0.0 through 10.4.17 and 11.0.0 through 11.3.0." );
	script_tag( name: "solution", value: "Update to version 7.6.52 ELTS, 8.7.41 ELTS, 9.5.28, 10.4.18,
  11.3.1 or later." );
	script_xref( name: "URL", value: "https://typo3.org/security/advisory/typo3-core-sa-2021-012" );
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
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.6.51" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.6.52 ELTS", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0.0", test_version2: "8.7.40" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.7.41 ELTS", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.0.0", test_version2: "9.5.27" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.5.28", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.0.0", test_version2: "10.4.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.4.18", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "11.0.0", test_version2: "11.3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.3.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

