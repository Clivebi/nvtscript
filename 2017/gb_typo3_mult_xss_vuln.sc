CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112112" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-08 13:15:49 +0100 (Wed, 08 Nov 2017)" );
	script_bugtraq_id( 42029 );
	script_cve_id( "CVE-2010-3659" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-07 20:14:00 +0000 (Tue, 07 Nov 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "TYPO3 Multiple XSS Vulnerabilities" );
	script_tag( name: "summary", value: "TYPO3 is prone to multiple cross-site scripting (XSS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple cross-site scripting (XSS) vulnerabilities in TYPO3 CMS allow remote authenticated backend users
  to inject arbitrary web script or HTML via unspecified parameters to the extension manager, or unspecified parameters to unknown backend forms." );
	script_tag( name: "affected", value: "TYPO3 CMS 4.1.x before 4.1.14, 4.2.x before 4.2.13, 4.3.x before 4.3.4, and 4.4.x before 4.4.1" );
	script_tag( name: "solution", value: "Update to TYPO3 version 4.1.14, 4.2.13, 4.3.4 or 4.4.1." );
	script_xref( name: "URL", value: "https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2010-012/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port, version_regex: "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(IsMatchRegexp( ver, "^4\\.1" )){
	if(version_in_range( version: ver, test_version: "4.1.0", test_version2: "4.1.13" )){
		fix = "4.1.14";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( ver, "^4\\.2" )){
	if(version_in_range( version: ver, test_version: "4.2.0", test_version2: "4.2.12" )){
		fix = "4.2.13";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( ver, "^4\\.3" )){
	if(version_in_range( version: ver, test_version: "4.3.0", test_version2: "4.3.3" )){
		fix = "4.3.4";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( ver, "^4\\.4" )){
	if(version_is_equal( version: ver, test_version: "4.4.0" )){
		fix = "4.4.1";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: ver, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

