CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815044" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_cve_id( "CVE-2019-5824", "CVE-2019-5825", "CVE-2019-5826", "CVE-2019-5827" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-02 10:48:59 +0530 (Thu, 02 May 2019)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_30-2019-04)-MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Parameter passing error in media player.

  - An out-of-bounds write error in V8.

  - An use-after-free error in IndexedDB.

  - An out-of-bounds access error in SQLite.

  - An integer overflow in SQLite via WebSQL in Google Chrome." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to execute arbitrary code in the context of the browser, Failed
  attempts will likely cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 74.0.3729.131 on MAC OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 74.0.3729.131 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_30.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "74.0.3729.131" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "74.0.3729.131", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

