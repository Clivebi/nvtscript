CPE = "cpe:/a:apple:quicktime";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807545" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-04-18 12:07:38 +0530 (Mon, 18 Apr 2016)" );
	script_name( "Apple QuickTime Multiple Remote Code Execution Vulnerabilities Apr16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple QuickTime
  and is prone to multiple remote code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A heap buffer overflow vulnerability in the 'moov atom'.

  - A heap buffer overfolw vulnerability in the 'atom processing'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code under the context of the QuickTime player." );
	script_tag( name: "affected", value: "Apple QuickTime version 7.7.9 and earlier
  on Windows." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT205771" );
	script_xref( name: "URL", value: "http://zerodayinitiative.com/advisories/ZDI-16-241" );
	script_xref( name: "URL", value: "http://zerodayinitiative.com/advisories/ZDI-16-242" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_quicktime_detection_win_900124.sc" );
	script_mandatory_keys( "QuickTime/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!quickVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: quickVer, test_version: "7.79.80.95" )){
	report = report_fixed_ver( installed_version: quickVer, fixed_version: "Uninstall Apple QuickTime" );
	security_message( data: report );
	exit( 0 );
}

