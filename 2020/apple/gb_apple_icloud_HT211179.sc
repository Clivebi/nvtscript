CPE = "cpe:/a:apple:icloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817029" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-9789", "CVE-2020-9790", "CVE-2020-3878", "CVE-2020-9794", "CVE-2020-9802", "CVE-2020-9805", "CVE-2020-9800", "CVE-2020-9806", "CVE-2020-9807", "CVE-2020-9850", "CVE-2020-9843", "CVE-2020-9803" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-11 14:25:00 +0000 (Thu, 11 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-05-27 12:24:11 +0530 (Wed, 27 May 2020)" );
	script_name( "Apple iCloud Security Update (HT211179)" );
	script_tag( name: "summary", value: "Apple iCloud is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An out-of-bounds write/read issues with bounds checking,

  - A memory corruption issues with input validation" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks." );
	script_tag( name: "affected", value: "Apple iCloud versions before 11.2" );
	script_tag( name: "solution", value: "Update to Apple iCloud 11.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT211179" );
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
if(version_is_less( version: vers, test_version: "11.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

