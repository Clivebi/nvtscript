CPE = "cpe:/a:apple:icloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810575" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2016-7583", "CVE-2016-4613", "CVE-2016-7578" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-25 17:13:00 +0000 (Mon, 25 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-02-28 10:49:30 +0530 (Tue, 28 Feb 2017)" );
	script_name( "Apple iCloud Code Execution And Information Disclosure Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple iCloud
  and is prone to multiple code execution and information disclosure
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple memory corruption errors in WebKit.

  - An input validation error in WebKit.

  - A dynamic library loading issue in iCloud setup." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code and disclose sensitive information." );
	script_tag( name: "affected", value: "Apple iCloud versions before 6.0.1
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Apple iCloud 6.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207273" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_apple_icloud_detect_win.sc" );
	script_mandatory_keys( "apple/icloud/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!icVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: icVer, test_version: "6.0.1" )){
	report = report_fixed_ver( installed_version: icVer, fixed_version: "6.0.1" );
	security_message( data: report );
	exit( 0 );
}

