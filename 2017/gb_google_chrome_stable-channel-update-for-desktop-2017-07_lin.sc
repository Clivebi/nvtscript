CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811540" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_cve_id( "CVE-2017-5091", "CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5094", "CVE-2017-5095", "CVE-2017-5096", "CVE-2017-5097", "CVE-2017-5098", "CVE-2017-5099", "CVE-2017-5100", "CVE-2017-5101", "CVE-2017-5102", "CVE-2017-5103", "CVE-2017-5104", "CVE-2017-7000", "CVE-2017-5105", "CVE-2017-5106", "CVE-2017-5107", "CVE-2017-5108", "CVE-2017-5109", "CVE-2017-5110" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-07-27 10:22:29 +0530 (Thu, 27 Jul 2017)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2017-07)-Linux" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use after free in IndexedDB.

  - Use after free in PPAPI.

  - UI spoofing in Blink.

  - Type confusion in extensions.

  - Out-of-bounds write in PDFium.

  - User information leak via Android intents.

  - Out-of-bounds read in Skia.

  - Use after free in V8.

  - Out-of-bounds write in PPAPI.

  - Use after free in Chrome Apps.

  - URL spoofing in OmniBox.

  - Uninitialized use in Skia.

  - UI spoofing in browser.

  - Pointer disclosure in SQLite.

  - User information leak via SVG.

  - Type confusion in PDFium.

  - UI spoofing in payments dialog.

  - Various fixes from internal audits, fuzzing and other initiatives." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to conduct spoofing attacks,
  disclose sensitive information, cause a program to crash and can
  potentially result in the execution of arbitrary code or even enable
  full remote code execution capabilities." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 60.0.3112.78 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  60.0.3112.78 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2017/07/stable-channel-update-for-desktop.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "60.0.3112.78" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "60.0.3112.78" );
	security_message( data: report );
	exit( 0 );
}

