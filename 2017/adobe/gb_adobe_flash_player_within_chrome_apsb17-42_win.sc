CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812253" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_cve_id( "CVE-2017-11305" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-12 02:29:00 +0000 (Fri, 12 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-12-13 12:57:31 +0530 (Wed, 13 Dec 2017)" );
	script_name( "Adobe Flash Player Within Google Chrome Security Update(apsb17-42)- Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw exists due to a logic error may
  cause the global settings preference file to be reset." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to conduct unintended reset of
  global settings preference file." );
	script_tag( name: "affected", value: "Adobe Flash Player prior to 28.0.0.126
  within Google Chrome on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player for
  Google Chrome 28.0.0.126, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb17-42.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "28.0.0.126" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "28.0.0.126", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

