CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817277" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-6558", "CVE-2020-6559", "CVE-2020-6560", "CVE-2020-6561", "CVE-2020-6562", "CVE-2020-6563", "CVE-2020-6564", "CVE-2020-6565", "CVE-2020-6566", "CVE-2020-6567", "CVE-2020-6568", "CVE-2020-6569", "CVE-2020-6570", "CVE-2020-6571" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-27 20:29:00 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:51:21 +0530 (Wed, 02 Sep 2020)" );
	script_name( "Google Chrome Security Update (stable-channel-update-for-desktop_25-2020-08) - Mac OS X" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - Insufficient policy enforcement in iOS.

  - Use after free in presentation API.

  - Insufficient policy enforcement in autofill.

  - Inappropriate implementation in Content Security Policy.

  - Insufficient policy enforcement in Blink.

  - Insufficient policy enforcement in intent handling.

  - Incorrect security UI in permissions.

  - Incorrect security UI in Omnibox.

  - Insufficient policy enforcement in media.

  - Insufficient validation of untrusted input in command line handling.

  - Integer overflow in WebUSB.

  - Side-channel information leakage in WebRTC." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  execute arbitrary code, disclose sensitive information and cause denial of service
  condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 85.0.4183.83." );
	script_tag( name: "solution", value: "Update to Google Chrome version
  85.0.4183.83 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2020/08/stable-channel-update-for-desktop_25.html" );
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
if(version_is_less( version: vers, test_version: "85.0.4183.83" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "85.0.4183.83", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

