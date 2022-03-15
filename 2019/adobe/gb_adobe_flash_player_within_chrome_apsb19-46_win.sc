CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815467" );
	script_version( "2021-08-30T13:01:21+0000" );
	script_cve_id( "CVE-2019-8070", "CVE-2019-8069" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 13:01:21 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-25 02:15:00 +0000 (Mon, 25 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-09-11 12:21:05 +0530 (Wed, 11 Sep 2019)" );
	script_name( "Adobe Flash Player Within Google Chrome Security Update(apsb19-46)- Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An use after free vulnerability.

  - Same Origin Method Execution (SOME) Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  conduct arbitrary code execution." );
	script_tag( name: "affected", value: "Adobe Flash Player prior to 32.0.0.255
  within Google Chrome on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player for Google Chrome
  32.0.0.255, or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb19-46.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_flash_player_within_google_chrome_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Chrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "32.0.0.255" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "32.0.0.255", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

