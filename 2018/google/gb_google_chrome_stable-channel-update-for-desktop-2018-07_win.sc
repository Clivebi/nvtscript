CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813801" );
	script_version( "2021-07-01T02:00:36+0000" );
	script_cve_id( "CVE-2018-6153", "CVE-2018-6154", "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157", "CVE-2018-6158", "CVE-2018-6159", "CVE-2018-6160", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163", "CVE-2018-6164", "CVE-2018-6165", "CVE-2018-6166", "CVE-2018-6167", "CVE-2018-6168", "CVE-2018-6169", "CVE-2018-6170", "CVE-2018-6171", "CVE-2018-6172", "CVE-2018-6173", "CVE-2018-6174", "CVE-2018-6175", "CVE-2018-6176", "CVE-2018-6177", "CVE-2018-6178", "CVE-2018-6179", "CVE-2018-6044", "CVE-2018-4117", "CVE-2018-6150", "CVE-2018-6151", "CVE-2018-6152", "CVE-2018-17460", "CVE-2018-16064" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-01 02:00:36 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-14 18:23:00 +0000 (Mon, 14 Jan 2019)" );
	script_tag( name: "creation_date", value: "2018-07-25 10:11:37 +0530 (Wed, 25 Jul 2018)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2018-07)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A stack buffer overflow error in Skia.

  - Multiple heap buffer overflow errors in WebGL and WebRTC.

  - Multiple use after free errors in Blink, WebRTC and WebBluetooth.

  - An improper validation of URL and UI.

  - Multiple type confusion errors in WebRTC and PDFium.

  - An integer overflow error in SwiftShader.

  - An improper serialization of data in DevTools.

  - Multiple security bypass errors.

  - An insufficient data validation in Extensions API and filesystem URIs in
    Google Chrome." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass secuirty restrictions, conduct spoofing attacks, disclose
  sensitive information and cause denial of service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 68.0.3440.75 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 68.0.3440.75
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2018/07/stable-channel-update-for-desktop.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
chr_ver = infos["version"];
chr_path = infos["location"];
if(version_is_less( version: chr_ver, test_version: "68.0.3440.75" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "68.0.3440.75", install_path: chr_path );
	security_message( data: report );
	exit( 0 );
}

