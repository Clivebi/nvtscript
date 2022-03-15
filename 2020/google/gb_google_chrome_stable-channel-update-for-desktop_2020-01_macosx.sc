CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815891" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-6377" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-19 03:15:00 +0000 (Sun, 19 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 12:07:40 +0530 (Thu, 09 Jan 2020)" );
	script_name( "Google Chrome Security Update (stable-channel-update-for-desktop_2020-01) - Mac OS X" );
	script_tag( name: "summary", value: "Google Chrome is prone to an use after free vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an use after free error in
  audio." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code or crash affected system." );
	script_tag( name: "affected", value: "Google Chrome version prior to 79.0.3945.117." );
	script_tag( name: "solution", value: "Update to Google Chrome version
  79.0.3945.117 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2020/01/stable-channel-update-for-desktop.html" );
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
if(version_is_less( version: vers, test_version: "79.0.3945.117" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "79.0.3945.117", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

