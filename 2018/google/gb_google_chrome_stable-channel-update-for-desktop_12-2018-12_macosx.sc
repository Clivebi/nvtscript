CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814556" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2018-1748" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2018-12-14 12:54:35 +0530 (Fri, 14 Dec 2018)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_12-2018-12)-MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist due to use after frees
  in PDFium.

  Note: Use after free in PDFium. Reported by Anonymous on 2018-11-04(This
  issue was first addressed in the initial Stable release of Chrome 70, but
  received additional fixes in this release 71.0.3578.98" );
	script_tag( name: "affected", value: "Google Chrome versions prior to 71.0.3578.98 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  71.0.3578.98 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop_12.html" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "71.0.3578.98" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "71.0.3578.98", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

