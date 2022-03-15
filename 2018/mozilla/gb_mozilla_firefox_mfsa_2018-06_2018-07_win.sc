CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813034" );
	script_version( "2021-07-01T02:00:36+0000" );
	script_cve_id( "CVE-2018-5127", "CVE-2018-5128", "CVE-2018-5129", "CVE-2018-5130", "CVE-2018-5131", "CVE-2018-5132", "CVE-2018-5133", "CVE-2018-5134", "CVE-2018-5135", "CVE-2018-5136", "CVE-2018-5137", "CVE-2018-5140", "CVE-2018-5141", "CVE-2018-5142", "CVE-2018-5143", "CVE-2018-5126", "CVE-2018-5125" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-01 02:00:36 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-06 17:58:00 +0000 (Mon, 06 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-03-15 11:20:29 +0530 (Thu, 15 Mar 2018)" );
	script_name( "Mozilla Firefox Security Updates(mfsa_2018-06_2018-07)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A buffer overflow error when manipulating SVG animatedPathSegList through script.

  - An use-after-free error during editor operations.

  - A lack of parameter validation on IPC messages.

  - A memory corruption error when packets with a mismatched RTP payload type are
    sent in WebRTC connections.

  - Fetch API improperly returns cached copies of no-store/no-cache resources.

  - The Find API for WebExtensions can search some privileged pages.

  - The value of the app.support.baseURL preference is not properly sanitized.

  - WebExtensions may use view-source: URLs to bypass content restrictions.

  - WebExtensions can bypass normal restrictions in some circumstances.

  - Same-origin policy violation with data: URL shared workers.

  - Script content can access legacy extension non-contentaccessible resources.

  - Moz-icon images accessible to web content through moz-icon: protocol.

  - A vulnerability in the notifications Push API.

  - Media Capture and Streams API permissions display incorrect origin with data: and blob: URLs.

  - Self-XSS pasting javascript: URL with embedded tab into addressbar.

  - Memory safety bugs fixed in Firefox 59." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct cross-site scripting (XSS) attacks, crash the affected
  system, conduct sandbox escape, access sensitive data and bypass security
  restrictions." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 59 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 59
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-06" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ffVer = infos["version"];
ffPath = infos["location"];
if(version_is_less( version: ffVer, test_version: "59" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "59", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

