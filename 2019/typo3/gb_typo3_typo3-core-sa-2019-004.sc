CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141926" );
	script_version( "$Revision: 13287 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-25 10:06:21 +0100 (Fri, 25 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2019-01-25 16:00:09 +0700 (Fri, 25 Jan 2019)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TYPO3 XSS Vulnerability (TYPO3-CORE-SA-2019-004)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_tag( name: "summary", value: "Failing to properly encode information from external sources, language pack
handling in the install tool is vulnerable to cross-site scripting." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "TYPO3 versions 9.2.0-9.5.3." );
	script_tag( name: "solution", value: "Update to version 9.5.4 or later." );
	script_xref( name: "URL", value: "https://typo3.org/security/advisory/typo3-core-sa-2019-004/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port, version_regex: "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.2.0", test_version2: "9.5.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.5.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

