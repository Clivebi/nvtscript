CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811080" );
	script_version( "2021-09-13T13:01:42+0000" );
	script_cve_id( "CVE-2017-5070", "CVE-2017-5071", "CVE-2017-5072", "CVE-2017-5073", "CVE-2017-5074", "CVE-2017-5075", "CVE-2017-5086", "CVE-2017-5076", "CVE-2017-5077", "CVE-2017-5078", "CVE-2017-5079", "CVE-2017-5080", "CVE-2017-5081", "CVE-2017-5082", "CVE-2017-5083", "CVE-2017-5085" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 13:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-06-06 10:00:35 +0530 (Tue, 06 Jun 2017)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2017-06)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A type confusion in V8.

  - An out of bounds read error in V8.

  - Address spoofing in Omnibox.

  - Use after free error in print preview.

  - Use after free error in Apps Bluetooth.

  - Information leak in CSP reporting.

  - Heap buffer overflow in Skia.

  - Possible command injection in mailto handling.

  - UI spoofing in Blink.

  - Use after free error in credit card autofill.

  - Extension verification bypass.

  - Insufficient hardening in credit card editor.

  - Inappropriate javascript execution on WebUI pages." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to have some unspecified impact on the affected user." );
	script_tag( name: "affected", value: "Google Chrome version prior to 59.0.3071.86 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 59.0.3071.86
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop.html" );
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
if(version_is_less( version: chr_ver, test_version: "59.0.3071.86" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "59.0.3071.86" );
	security_message( data: report );
	exit( 0 );
}

