CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816705" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6811", "CVE-2019-20503", "CVE-2020-6812", "CVE-2020-6814" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-22 20:15:00 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-03-16 14:57:10 +0530 (Mon, 16 Mar 2020)" );
	script_name( "Mozilla Thunderbird Security Update (mfsa_2020-10) - Windows" );
	script_tag( name: "summary", value: "Mozilla Thunderbird is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A use-after-free when removing data about origins.

  - Multiple out-of-bounds read issues.

  - A use-after-free issue in cubeb during stream destruction.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  disclose sensitive information, run arbitrary code, inject arbitrary commands
  and crash the affected system." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 68.6." );
	script_tag( name: "solution", value: "Update to Mozilla Thunderbird version 68.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2020-10/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "68.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "68.6", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

