CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817441" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-6537", "CVE-2020-6538", "CVE-2020-6532", "CVE-2020-6539", "CVE-2020-6540", "CVE-2020-6541" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-16 14:13:00 +0000 (Tue, 16 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-08-12 14:29:15 +0530 (Wed, 12 Aug 2020)" );
	script_name( "Google Chrome Security Update (stable-channel-update-for-desktop_27-2020-07) - Mac OS X" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Type Confusion in V8.

  - Inappropriate implementation in WebView.

  - Use after free in SCTP.

  - Use after free in CSS.

  - Heap buffer overflow in Skia.

  - Use after free in WebUSB." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  execute arbitrary code, disclose sensitive information and cause denial of service
  condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 84.0.4147.105." );
	script_tag( name: "solution", value: "Update to Google Chrome version 84.0.4147.105 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2020/07/stable-channel-update-for-desktop_27.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "84.0.4147.105" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "84.0.4147.105", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

