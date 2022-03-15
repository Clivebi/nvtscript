CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803990" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_cve_id( "CVE-2009-3628", "CVE-2009-3629", "CVE-2009-3630", "CVE-2009-3631", "CVE-2009-3632", "CVE-2009-3633", "CVE-2009-3635", "CVE-2009-3636" );
	script_bugtraq_id( 36801 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-27 12:45:17 +0530 (Fri, 27 Dec 2013)" );
	script_name( "TYPO3 Multiple Vulnerabilities Oct09" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal the
victim's cookie-based authentication credentials or execute arbitrary code." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors exist in the application:

  - Multiple errors in Backend subcomponent, which fails to validate user
supplied input properly.

  - An error exists in Frontend Editing, which fails to sanitize URL parameters
properly.

  - An error exists in API function t3lib_div::quoteJSvalue, which fails to
validate user supplied input properly.

  - Multiple errors exist in Install Tool, which allows login with know md5 hash of
Install Tool password." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.1.13, 4.2.10, 4.3beta2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "TYPO3 versions 4.0.13 and below, 4.1.0 to 4.1.12, 4.2.0 to 4.2.9 and 4.3.0beta1" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53917" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37122" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2009-016/" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
	if(version_is_less( version: typoVer, test_version: "4.1.13" ) || version_in_range( version: typoVer, test_version: "4.2.0", test_version2: "4.2.9" )){
		security_message( typoPort );
		exit( 0 );
	}
}

