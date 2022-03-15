CPE = "cpe:/a:apple:icloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816718" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-3910", "CVE-2020-3909", "CVE-2020-3911", "CVE-2020-3901", "CVE-2020-3887", "CVE-2020-3895", "CVE-2020-3900", "CVE-2020-3894", "CVE-2020-3897", "CVE-2020-9783", "CVE-2020-3899", "CVE-2020-3902", "CVE-2020-3885" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 17:15:00 +0000 (Fri, 16 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-03-26 16:15:07 +0530 (Thu, 26 Mar 2020)" );
	script_name( "Apple iCloud Security Update (HT211106)" );
	script_tag( name: "summary", value: "Apple iCloud is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple buffer overflow issues due to improper size validation and bounds checking.

  - A type confusion issue due to improper memory handling.

  - A logic issue improper restrictions.

  - A memory corruption issue due to improper memory handling.

  - A race condition issue due to insufficient validation.

  - A use after free issue due to improper memory management.

  - A memory consumption issue due to improper memory handling.

  - An input validation issue due to improper validation." );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers
  to execute arbitrary code, read restricted memory, and launch cross site scripting
  attacks." );
	script_tag( name: "affected", value: "Apple iCloud versions before 10.9.3" );
	script_tag( name: "solution", value: "Update to Apple iCloud 10.9.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT211106" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^10\\." ) && version_is_less( version: vers, test_version: "10.9.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.9.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

