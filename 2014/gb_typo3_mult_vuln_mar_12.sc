CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803998" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_cve_id( "CVE-2012-1606", "CVE-2012-1607", "CVE-2012-1608" );
	script_bugtraq_id( 52771 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-01-02 17:09:08 +0530 (Thu, 02 Jan 2014)" );
	script_name( "TYPO3 Multiple Vulnerabilities Mar12" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials or get sensitive information." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors exist in the application:

  - An error exists in Backend, which fails to validate user supplied input
properly.

  - An error exists in Command Line Interface script, which on directly accessed
with a browser may disclose the database name

  - An error exists in HTML Sanitizing API, which fails to validate user supplied
input properly." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.4.14, 4.5.14 4.6.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "TYPO3 version 4.4.0 to 4.4.13, 4.5.0 to 4.5.13 and 4.6.0 to 4.6.6" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2012/03/30/4" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2012-001" );
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
	if(version_in_range( version: typoVer, test_version: "4.4.0", test_version2: "4.4.13" ) || version_in_range( version: typoVer, test_version: "4.5.0", test_version2: "4.5.13" ) || version_in_range( version: typoVer, test_version: "4.6.0", test_version2: "4.6.6" )){
		security_message( typoPort );
		exit( 0 );
	}
}

