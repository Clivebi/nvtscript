CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812263" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_cve_id( "CVE-2017-15429" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-07 19:02:00 +0000 (Wed, 07 Nov 2018)" );
	script_tag( name: "creation_date", value: "2017-12-15 12:34:34 +0530 (Fri, 15 Dec 2017)" );
	script_name( "Google Chrome Security Updates (stable-channel-update-for-desktop-2017-12-1) - Mac OS X" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An input validation error in V8.

  - Various fixes from internal audits, fuzzing and other initiatives." );
	script_tag( name: "impact", value: "Successful exploitation of these vulnerabilities will allow
  remote attackers to execute arbitrary script and cause some unspecified impact." );
	script_tag( name: "affected", value: "Google Chrome version prior to 63.0.3239.108." );
	script_tag( name: "solution", value: "Update to Google Chrome 63.0.3239.108 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2017/12/stable-channel-update-for-desktop_14.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "63.0.3239.108" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "63.0.3239.108", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

