CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804206" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_cve_id( "CVE-2013-7073", "CVE-2013-7074", "CVE-2013-7075", "CVE-2013-7078", "CVE-2013-7079", "CVE-2013-7081" );
	script_bugtraq_id( 64240, 64245, 64256, 64239, 64252, 64238 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-01-06 15:22:20 +0530 (Mon, 06 Jan 2014)" );
	script_name( "TYPO3 Multiple Vulnerabilities Dec13" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to get sensitive
information or execute arbitrary script code." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors exist in the application:

  - Multiple errors exist in Content Editing Wizard, which fails to check user
permissions, properly encode user input and which misses signature for an
input parameter.

  - An error exists in Extbase Framework, which returns error messages without
properly encoding.

  - An error exists in openid extension, which allows redirection to arbitrary
URL.

  - An error exists in form content element, which allows generation of arbitrary
signatures that could be used in a different context." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.5.32, 4.7.17, 6.0.12, 6.1.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "TYPO3 version 4.5.0 to 4.5.31, 4.7.0 to 4.7.16, 6.0.0 to 6.0.11, 6.1.0 to
6.1.6" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55958/" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2013-004" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!typoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(typoVer = get_app_version( cpe: CPE, port: typoPort )){
	if(!IsMatchRegexp( typoVer, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
		exit( 0 );
	}
	if(version_in_range( version: typoVer, test_version: "4.5.0", test_version2: "4.5.31" ) || version_in_range( version: typoVer, test_version: "4.7.0", test_version2: "4.7.16" ) || version_in_range( version: typoVer, test_version: "6.0.0", test_version2: "6.0.11" ) || version_in_range( version: typoVer, test_version: "6.1.0", test_version2: "6.1.6" )){
		security_message( typoPort );
		exit( 0 );
	}
}

