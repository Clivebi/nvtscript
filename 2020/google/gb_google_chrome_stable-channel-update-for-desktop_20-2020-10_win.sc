CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817518" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-16000", "CVE-2020-16001", "CVE-2020-16002", "CVE-2020-15999", "CVE-2020-16003" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-17 13:04:00 +0000 (Wed, 17 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-10-21 10:23:51 +0530 (Wed, 21 Oct 2020)" );
	script_name( "Google Chrome Security Update (stable-channel-update-for-desktop_20-2020-10) - Windows" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Inappropriate implementation in Blink.

  - Use after free in media.

  - Use after free in PDFium.

  - Heap buffer overflow in Freetype.

  - Use after free in printing." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code or crash affected system." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 86.0.4240.111." );
	script_tag( name: "solution", value: "Update to Google Chrome version
  86.0.4240.111 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2020/10/stable-channel-update-for-desktop_20.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "86.0.4240.111" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "86.0.4240.111", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

