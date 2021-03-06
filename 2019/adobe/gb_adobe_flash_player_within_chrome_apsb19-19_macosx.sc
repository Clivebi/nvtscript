CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815032" );
	script_version( "2021-08-30T13:01:21+0000" );
	script_cve_id( "CVE-2019-7108", "CVE-2019-7096" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 13:01:21 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-18 05:15:00 +0000 (Sun, 18 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-04-10 11:01:46 +0530 (Wed, 10 Apr 2019)" );
	script_name( "Adobe Flash Player Within Google Chrome Security Update(apsb19-19)- MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An out of bounds read error.

  - An use after free error." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers
  to disclose sensitive information and execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Flash Player prior to 32.0.0.171
  within Google Chrome on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player for Google Chrome
  32.0.0.171, or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb19-19.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_flash_player_within_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Chrome/MacOSX/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "32.0.0.156" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "32.0.0.171", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

