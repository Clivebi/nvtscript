CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814018" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2018-09-17 11:22:42 +0530 (Mon, 17 Sep 2018)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2018-09_11)-Mac OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - URL spoof in Omnibox.

  - Function signature mismatch in WebAssembly." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers
  to conduct spoofing attacks and bypass security restrictions." );
	script_tag( name: "affected", value: "Google Chrome version prior to 69.0.3497.92
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  69.0.3497.92 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2018/09/stable-channel-update-for-desktop_11.html" );
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
if(version_is_less( version: chr_ver, test_version: "69.0.3497.92" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "69.0.3497.92", install_path: chr_path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

