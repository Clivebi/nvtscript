CPE = "cpe:/a:apple:icloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810983" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_cve_id( "CVE-2017-2493", "CVE-2017-2480", "CVE-2017-2479", "CVE-2017-2463", "CVE-2017-5029", "CVE-2017-2383" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-19 13:38:00 +0000 (Tue, 19 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-05-16 14:51:38 +0530 (Tue, 16 May 2017)" );
	script_name( "Apple iCloud Multiple Vulnerabilities-HT207607 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A validation issue existed in element handling.

  - Multiple memory corruption issues.

  - Poor certificate handling." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to execute arbitrary code, track a user's activity and exfiltrate
  data cross-origin." );
	script_tag( name: "affected", value: "Apple iCloud versions before 6.2
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Apple iCloud 6.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207607" );
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
if(version_is_less( version: icVer, test_version: "6.2" )){
	report = report_fixed_ver( installed_version: icVer, fixed_version: "6.2" );
	security_message( data: report );
	exit( 0 );
}

