CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814622" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493", "CVE-2018-18494", "CVE-2018-18498", "CVE-2018-12405" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-11 15:00:00 +0000 (Mon, 11 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-12-13 11:24:30 +0530 (Thu, 13 Dec 2018)" );
	script_name( "Mozilla Firefox ESR Security Update (mfsa_2018-29_2018-30) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox ESR is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Check if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Buffer overflow and out-of-bounds read errors in ANGLE library with
    TextureStorage11.

  - An use-after-free error with select element.

  - Buffer overflow error in accelerated 2D canvas with Skia.

  - Same-origin policy violation using location attribute and performance.getEntries
    to steal cross-origin URLs." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  run arbitrary code, bypass security restrictions and cause denial of service
  condition." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 60.4 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox ESR 60.4 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-30" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_win.sc", "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "60.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "60.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

