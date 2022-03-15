CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815712" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2019-15903", "CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-14 19:15:00 +0000 (Sat, 14 Mar 2020)" );
	script_tag( name: "creation_date", value: "2019-10-23 13:07:06 +0530 (Wed, 23 Oct 2019)" );
	script_name( "Mozilla Firefox ESR Security Update (mfsa_2019-33_2019-34) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox ESR is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A heap overflow issue in expat library in XML_GetCurrentLineNumber.

  - A use-after-free issue when creating index updates in IndexedDB.

  - A stack buffer overflow issue in HKDF output and WebRTC networking.

  - A unintended access issue to a privileged JSONView object.

  - A same-origin-property violation issue in document.domain-based origin
    isolation.

  - An incorrect HTML parsing issue.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers run arbitrary code, crash the application,
  bypass security restrictions and conduct cross-site scripting attacks." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 68.2 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox ESR version 68.2
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-33/" );
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
if(version_is_less( version: vers, test_version: "68.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "68.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

