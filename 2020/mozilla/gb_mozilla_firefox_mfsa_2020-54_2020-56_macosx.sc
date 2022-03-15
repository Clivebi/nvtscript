CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817555" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-16042", "CVE-2020-26971", "CVE-2020-26972", "CVE-2020-26973", "CVE-2020-26974", "CVE-2020-26975", "CVE-2020-26976", "CVE-2020-26977", "CVE-2020-26978", "CVE-2020-26979", "CVE-2020-35111", "CVE-2020-35112", "CVE-2020-35113", "CVE-2020-35114" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-11 19:39:00 +0000 (Mon, 11 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-12-16 11:15:14 +0530 (Wed, 16 Dec 2020)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2020-54_2020-56) - Mac OS X" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Operations on a BigInt could have caused uninitialized memory to be exposed.

  - Heap buffer overflow in WebGL.

  - Use-After-Free in WebGL.

  - CSS Sanitizer performed incorrect sanitization.

  - Incorrect cast of StyleGenericFlexBasis resulted in a heap use-after-free.

  - Malicious applications on Android could have induced Firefox for Android into sending arbitrary attacker-specified headers.

  - HTTPS pages could have been intercepted by a registered service worker when they should not have been.

  - URL spoofing via unresponsive port in Firefox for Android.

  - Internal network hosts could have been probed by a malicious webpage.

  - When entering an address in the address or search bars, a website could have redirected the user before they were navigated to the intended url.

  - The proxy.onRequest API did not catch view-source URLs.

  - Opening an extension-less download may have inadvertently launched an executable instead.

  - Memory safety bugs fixed in Firefox 84 and Firefox ESR 78.6.

  - Memory safety bugs fixed in Firefox 84." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct a denial-of-service, execute arbitrary code or information disclosure
  on affected system." );
	script_tag( name: "affected", value: "Mozilla Firefox version before
  84." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox version 84
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2020-54/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "84" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "84", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

