CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818023" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-21191", "CVE-2021-21192", "CVE-2021-21193" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)" );
	script_tag( name: "creation_date", value: "2021-02-23 10:52:28 +0530 (Tue, 23 Feb 2021)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_12-2021-03)-MAC OS X" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - Use after free in WebRTC.

  - Heap buffer overflow in tab groups.

  - Use after free in Blink." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 89.0.4389.90 on MAC OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  89.0.4389.90 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2021/03/stable-channel-update-for-desktop_12.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "89.0.4389.90" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "89.0.4389.90", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

