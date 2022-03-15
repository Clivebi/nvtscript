CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815004" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9794", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9801", "CVE-2018-1850", "CVE-2019-9788" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:39:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-03-20 12:39:18 +0530 (Wed, 20 Mar 2019)" );
	script_name( "Mozilla Firefox ESR Security Update (mfsa_2019-06_2019-08) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox ESR is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An Use-after-free error when removing in-use DOM elements.

  - Type inference is incorrect for constructors entered through on-stack replacement with IonMonkey.

  - An error in IonMonkey just-in-time (JIT) compiler.

  - An improper bounds checks when Spectre mitigations are disabled.

  - Command line arguments not discarded during execution.

  - A type-confusion error in IonMonkey JIT compiler.

  - An use-after-free error with SMIL animation controller.

  - Windows programs that are not 'URL Handlers' are exposed to web content.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers
  to run arbitrary code, crash the system and bypass security restrictions." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before
  60.6 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox ESR version 60.6
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-08" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "60.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "60.6", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

