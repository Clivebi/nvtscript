CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811804" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2017-5111", "CVE-2017-5112", "CVE-2017-5113", "CVE-2017-5114", "CVE-2017-5115", "CVE-2017-5116", "CVE-2017-5117", "CVE-2017-5118", "CVE-2017-5119", "CVE-2017-5120" );
	script_bugtraq_id( 100610 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-31 02:29:00 +0000 (Sun, 31 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-09-07 11:46:45 +0530 (Thu, 07 Sep 2017)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2017-09)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An use after free error in PDFium.

  - A heap buffer overflow error in WebGL.

  - A heap buffer overflow error in Skia.

  - A Memory lifecycle issue in PDFium.

  - A type confusion error in V8.

  - Use of uninitialized value in Skia.

  - Bypass of Content Security Policy in Blink.

  - Potential HTTPS downgrade during redirect navigation.

  - Various fixes from internal audits, fuzzing and other initiatives." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary commands,
  corrupt memory and bypass security restrictions." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 61.0.3163.79 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  61.0.3163.79 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2017/09/stable-channel-update-for-desktop.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "61.0.3163.79" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "61.0.3163.79" );
	security_message( data: report );
	exit( 0 );
}

