CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146489" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 04:05:03 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-19 15:51:00 +0000 (Thu, 19 Aug 2021)" );
	script_cve_id( "CVE-2021-32768" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TYPO3 XSS Vulnerability (TYPO3-CORE-SA-2021-013)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_tag( name: "summary", value: "TYPO3 is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Failing to properly parse, sanitize and encode malicious
  rich-text content, the content rendering process in the website frontend is vulnerable to
  cross-site scripting. Corresponding rendering instructions via TypoScript functionality
  HTMLparser do not consider all potentially malicious HTML tag & attribute combinations per
  default.

  In addition, the lack of comprehensive default node configuration for rich-text fields in the
  backend user interface fosters this malfunction.

  In default scenarios, a valid backend user account is needed to exploit this vulnerability. In
  case custom plugins used in the website frontend accept and reflect rich-text content submitted
  by users, no authentication is required." );
	script_tag( name: "affected", value: "TYPO3 version 7.0.0 through 7.6.52 ELTS, 8.0.0 through
  8.7.41 ELTS, 9.0.0 through 9.5.28, 10.0.0 through 10.4.18 and 11.0.0 through 11.3.1." );
	script_tag( name: "solution", value: "Update to version 7.6.53 ELTS, 8.7.42 ELTS, 9.5.29, 10.4.19,
  11.3.2 or later." );
	script_xref( name: "URL", value: "https://typo3.org/security/advisory/typo3-core-sa-2021-013" );
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
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.6.52" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.6.53 ELTS", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0.0", test_version2: "8.7.41" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.7.42 ELTS", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.0.0", test_version2: "9.5.28" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.5.29", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.0.0", test_version2: "10.4.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.4.19", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "11.0.0", test_version2: "11.3.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.3.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

