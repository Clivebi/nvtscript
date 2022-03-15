CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814366" );
	script_version( "2021-07-01T02:00:36+0000" );
	script_cve_id( "CVE-2018-17480", "CVE-2018-17481", "CVE-2018-18335", "CVE-2018-18336", "CVE-2018-18337", "CVE-2018-18338", "CVE-2018-18339", "CVE-2018-18340", "CVE-2018-18341", "CVE-2018-18342", "CVE-2018-18343", "CVE-2018-18344", "CVE-2018-18345", "CVE-2018-18346", "CVE-2018-18347", "CVE-2018-18348", "CVE-2018-18349", "CVE-2018-18350", "CVE-2018-18351", "CVE-2018-18352", "CVE-2018-18354", "CVE-2018-18355", "CVE-2018-18356", "CVE-2018-18357", "CVE-2018-18358", "CVE-2018-18359" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-01 02:00:36 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-17 21:15:00 +0000 (Sat, 17 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-12-05 14:55:39 +0530 (Wed, 05 Dec 2018)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2018-12)-MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple out of bounds write error in V8.

  - Multiple use after free errors in PDFium, Blink, WebAudio, MediaRecorder,
    Skia and Extensions.

  - Multiple heap buffer overflow errors in Skia, Canvas and Blink.

  - Inappropriate implementations in Extensions, Site Isolation, Navigation,
    Omnibox, Media, Network Authentication and PDFium.

  - Multiple issues in SQLite via WebSQL.

  - Incorrect security UI in Blink.

  - Insufficient policy enforcements in Blink, Navigation, URL Formatter,
    Proxy and Payments.

  - Insufficient data validation in Shell Integration." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to execute arbitrary code in the context of the browser, obtain
  sensitive information, bypass security restrictions and perform unauthorized
  actions, or cause denial-of-service conditions" );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 71.0.3578.80 on MAC OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  71.0.3578.80 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "71.0.3578.80" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "71.0.3578.80", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

