CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817894" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_cve_id( "CVE-2021-23953", "CVE-2021-23954", "CVE-2021-23964", "CVE-2021-23960", "CVE-2020-26976" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-03 20:58:00 +0000 (Wed, 03 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-01-27 11:42:39 +0530 (Wed, 27 Jan 2021)" );
	script_name( "Mozilla Firefox ESR Security Update (mfsa_2021-02_2021-05) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox ESR is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Type confusion when using logical assignment operators in JavaScript switch
    statements.

  - Cross-origin information leakage via redirected PDF requests.

  - HTTPS pages could have been intercepted by a registered service worker when
    they should not have been.

  - Use-after-poison for incorrectly redeclared JavaScript variables during GC.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service and disclose sensitive
  information." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before
  78.7 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox ESR version 78.7
  or later, Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2021-04/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "78.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "78.7", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

