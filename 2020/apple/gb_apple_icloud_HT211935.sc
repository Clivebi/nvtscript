CPE = "cpe:/a:apple:icloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817872" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-10002", "CVE-2020-13434", "CVE-2020-13435", "CVE-2020-13630", "CVE-2020-13631", "CVE-2020-27911", "CVE-2020-27912", "CVE-2020-27917", "CVE-2020-27918", "CVE-2020-9849", "CVE-2020-9876", "CVE-2020-9947", "CVE-2020-9951", "CVE-2020-9961", "CVE-2020-9981", "CVE-2020-9983" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-10 13:47:00 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-12-08 14:23:33 +0530 (Tue, 08 Dec 2020)" );
	script_name( "Apple iCloud Security Update (HT211935)" );
	script_tag( name: "summary", value: "Apple iCloud is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple use after free issues due to improper memory management.

  - Multiple out-of-bounds write errors due to improper input validation and
    bounds checking.

  - An integer overflow error due to improper validation.

  - An information disclosure issue due to improper state management.

  - Memory corruption and logic issues due to improper state management." );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers
  to execute arbitrary code, read arbitrary files, and launch denial of service
  attacks." );
	script_tag( name: "affected", value: "Apple iCloud versions before 11.5" );
	script_tag( name: "solution", value: "Update to Apple iCloud 11.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT211935" );
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
if(version_is_less( version: vers, test_version: "11.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.5", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

