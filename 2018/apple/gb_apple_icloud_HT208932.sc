CPE = "cpe:/a:apple:icloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813559" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_cve_id( "CVE-2018-4293", "CVE-2018-4270", "CVE-2018-4284", "CVE-2018-4278", "CVE-2018-4266", "CVE-2018-4261", "CVE-2018-4262", "CVE-2018-4263", "CVE-2018-4264", "CVE-2018-4265", "CVE-2018-4267", "CVE-2018-4272", "CVE-2018-4271", "CVE-2018-4273" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-04 19:35:00 +0000 (Thu, 04 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-07-10 13:35:57 +0530 (Tue, 10 Jul 2018)" );
	script_name( "Apple iCloud Security Updates(HT208932)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A cookie management issue in improved checks.

  - A memory corruption issue in memory handling.

  - Sound fetched through audio elements exfiltrated cross-origin.

  - A type confusion issue in memory handling.

  - A race condition in validation.

  - Multiple memory corruption issues in memory handling.

  - Multiple memory corruption issues in input validation." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to crash Safari, exfiltrate audio data cross-origin, execute arbitrary code and
  cause a denial of service." );
	script_tag( name: "affected", value: "Apple iCloud versions before 7.6 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Apple iCloud 7.6 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208932" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_apple_icloud_detect_win.sc" );
	script_mandatory_keys( "apple/icloud/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
icVer = infos["version"];
icPath = infos["location"];
if(version_is_less( version: icVer, test_version: "7.6.0.15" )){
	report = report_fixed_ver( installed_version: icVer, fixed_version: "7.6", install_path: icPath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

