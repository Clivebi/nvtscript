CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815448" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_cve_id( "CVE-2019-11740", "CVE-2019-11746", "CVE-2019-11744", "CVE-2019-11742", "CVE-2019-11735", "CVE-2019-11734", "CVE-2019-11752", "CVE-2019-9812", "CVE-2019-11741", "CVE-2019-11743", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-5849", "CVE-2019-11750", "CVE-2019-11737", "CVE-2019-11738", "CVE-2019-11747" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-04 18:15:00 +0000 (Fri, 04 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-09-05 13:00:57 +0530 (Thu, 05 Sep 2019)" );
	script_name( "Mozilla Firefox Security Updates(mfsa_2019-25_2019-27)-Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Memory safety bugs.

  - Multiple use-after-free errors.

  - A same-origin policy violation.

  - Sandbox escape through Firefox Sync.

  - A compromised sandboxed content process.

  - Navigation events were not fully adhering to the W3C's 'Navigation-Timing Level 2'
    draft specification in some instances for the unload event.

  - A vulnerability exists in WebRTC where malicious web content can use probing
    techniques on the getUserMedia API using constraints.

  - An out-of-bounds read vulnerability exists in the Skia graphics library.

  - A type confusion vulnerability exists in Spidermonkey.

  - Content security policy directives ignore port and path if host is a wildcard.

  - Content security policy bypass through hash-based sources in directives.

  - 'Forget about this site' removes sites from pre-loaded HSTS list." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  cause denial of service, escalate privileges, conduct cross site scripting
  attacks and disclose sensitive information." );
	script_tag( name: "affected", value: "Mozilla Firefox version before
  69 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 69
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-25" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "69" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "69", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

