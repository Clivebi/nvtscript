CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813619" );
	script_version( "2021-07-01T02:00:36+0000" );
	script_cve_id( "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-5156", "CVE-2018-12370", "CVE-2018-5186", "CVE-2018-5187", "CVE-2018-5188", "CVE-2018-12361", "CVE-2018-12358", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12367", "CVE-2018-12368", "CVE-2018-12369", "CVE-2018-12371" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-01 02:00:36 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-06-27 16:01:13 +0530 (Wed, 27 Jun 2018)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2018-15_2018-17) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Buffer overflow error using computed size of canvas element.

  - Multiple use-after-free errors.

  - Multiple integer overflow errors.

  - Same-origin bypass error using service worker and redirection.

  - Compromised IPC child process can list local filenames.

  - Media recorder segmentation fault error when track type is changed during capture.

  - Invalid data handling during QCMS transformations.

  - No warning when opening executable SettingContent-ms files.

  - Timing attack mitigation of PerformanceNavigationTiming.

  - WebExtensions bundled with embedded experiments were not correctly checked
    for proper authorization.

  - In Reader View SameSite cookie protections are not checked on exiting.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code, bypass CSRF protections, disclose sensitive
  information and cause denial of service condition." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 61 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox version 61 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-15" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_win.sc", "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "61" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "61", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

