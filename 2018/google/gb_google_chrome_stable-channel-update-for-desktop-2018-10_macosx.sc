CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814096" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-5179", "CVE-2018-17477", "CVE-2018-17476", "CVE-2018-17475", "CVE-2018-17474", "CVE-2018-17473", "CVE-2018-17462", "CVE-2018-17471", "CVE-2018-17470", "CVE-2018-17469", "CVE-2018-17468", "CVE-2018-17467", "CVE-2018-17466", "CVE-2018-17465", "CVE-2018-17464", "CVE-2018-17463" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-17 11:15:41 +0530 (Wed, 17 Oct 2018)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2018-10)-Mac OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Sandbox escape in AppCache.

  - An input validation error in V8.

  - Heap buffer overflow error in Little CMS in PDFium.

  - Multiple URL and UI spoofing errors in Omnibox and Extensions.

  - Multiple memory corruption errors in Angle and GPU Internals.

  - Multiple use after free errors in V8 and Blink.

  - Lack of limits on 'update' function in ServiceWorker.

  - Security UI occlusion in full screen mode." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass security restrictions, execute arbitrary code, conduct spoofing attack
  and cause denial of service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 70.0.3538.67 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 70.0.3538.67
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2018/10/stable-channel-update-for-desktop.html" );
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
chr_ver = infos["version"];
chr_path = infos["location"];
if(version_is_less( version: chr_ver, test_version: "70.0.3538.67" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "70.0.3538.67", install_path: chr_path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

