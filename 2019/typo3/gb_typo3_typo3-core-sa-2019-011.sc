CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142396" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-10 09:20:37 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-13 17:29:00 +0000 (Mon, 13 May 2019)" );
	script_cve_id( "CVE-2019-11832", "CVE-2020-15241" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TYPO3 Multiple Vulnerabilities (TYPO3-CORE-SA-2019-011, TYPO3-CORE-SA-2019-012, TYPO3-CORE-SA-2019-013)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_tag( name: "summary", value: "TYPO3 is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "TYPO3 is prone to multiple vulnerabilities:

  - Security Misconfiguration in User Session Handling

  - Possible Arbitrary Code Execution in Image Processing (CVE-2019-11832)

  - Cross-Site scripting in the included TYPO3 Fluid Engine (package 'typo3fluid/fluid') (CVE-2020-15241)" );
	script_tag( name: "affected", value: "TYPO3 versions 8.0.0-8.7.24 and 9.0.0-9.5.5." );
	script_tag( name: "solution", value: "Update to version 8.7.25, 9.5.6 or later." );
	script_xref( name: "URL", value: "https://typo3.org/security/advisory/typo3-core-sa-2019-011/" );
	script_xref( name: "URL", value: "https://typo3.org/security/advisory/typo3-core-sa-2019-012/" );
	script_xref( name: "URL", value: "https://typo3.org/security/advisory/typo3-core-sa-2019-013/" );
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
path = infos["location"];
if( version_in_range( version: version, test_version: "8.0.0", test_version2: "8.7.24" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.7.25", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(version_in_range( version: version, test_version: "9.0.0", test_version2: "9.5.5" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.5.6", install_path: path );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

