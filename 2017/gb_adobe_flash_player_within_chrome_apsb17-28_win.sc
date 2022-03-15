CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811684" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2017-11281", "CVE-2017-11282" );
	script_bugtraq_id( 100710, 100716 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-14 17:40:00 +0000 (Thu, 14 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-09-13 11:00:56 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Adobe Flash Player Within Google Chrome Security Update(apsb17-28)- Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to memory corruption
  vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to perform code execution." );
	script_tag( name: "affected", value: "Adobe Flash Player prior to 27.0.0.130
  within Google Chrome on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player for
  Google Chrome 27.0.0.130, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb17-28.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_flash_player_within_google_chrome_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Chrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!playerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: playerVer, test_version: "27.0.0.130" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "27.0.0.130" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

