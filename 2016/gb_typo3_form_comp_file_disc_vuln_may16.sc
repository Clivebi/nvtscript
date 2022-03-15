CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807829" );
	script_version( "2019-07-24T08:39:52+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-24 08:39:52 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-05-20 18:19:17 +0530 (Fri, 20 May 2016)" );
	script_name( "TYPO3 Form Component Arbitrary File Disclosure Vulnerability May16 (SA-2016-010)" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and
  is prone to arbitrary file disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  the form component which fails to properly validate user input." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to read arbitrary files on the affected system." );
	script_tag( name: "affected", value: "TYPO3 versions 6.2.0 through 6.2.19" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 6.2.20
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://typo3.org/security/advisory/typo3-core-sa-2016-010/" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( typoVer, "^6\\.2" )){
	if(version_in_range( version: typoVer, test_version: "6.2.0", test_version2: "6.2.19" )){
		report = report_fixed_ver( installed_version: typoVer, fixed_version: "6.2.20" );
		security_message( port: typoPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

