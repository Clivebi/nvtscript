CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805247" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-9508", "CVE-2014-9509" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-01-19 12:19:42 +0530 (Mon, 19 Jan 2015)" );
	script_name( "TYPO3 Multiple Vulnerabilities-01 Jan-2015 (SA-2014-003)" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Certain input passed to the homepage is not properly sanitised before being
    used to generate anchor links.

  - An error related to the 'config.prefixLocalAnchors' configuration option." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to poison the cache and conduct spoofing attacks." );
	script_tag( name: "affected", value: "TYPO3 versions 4.5.x before 4.5.39, 4.6.x
  through 6.2.x before 6.2.9, and 7.x before 7.0.2" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.5.39 or 6.2.9
  or 7.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/60371" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2014-003" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(!typoVer = get_app_version( cpe: CPE, port: typoPort )){
	exit( 0 );
}
if(!IsMatchRegexp( typoVer, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(version_in_range( version: typoVer, test_version: "4.5.0", test_version2: "4.5.38" ) || version_in_range( version: typoVer, test_version: "4.6.0", test_version2: "6.2.8" ) || version_in_range( version: typoVer, test_version: "7.0.0", test_version2: "7.0.1" )){
	report = report_fixed_ver( installed_version: typoVer, fixed_version: "4.5.39/6.2.9/7.0.2" );
	security_message( port: typoPort, data: report );
	exit( 0 );
}
exit( 99 );

