CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810637" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_cve_id( "CVE-2016-7855" );
	script_bugtraq_id( 93861 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-16 17:14:00 +0000 (Thu, 16 May 2019)" );
	script_tag( name: "creation_date", value: "2017-03-17 17:08:34 +0530 (Fri, 17 Mar 2017)" );
	script_name( "Adobe Flash Player Within Google Chrome Security Update (apsb16-36) - Linux" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a use-after-free
  vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to take control of the affected system." );
	script_tag( name: "affected", value: "Adobe Flash Player for chrome versions
  before 23.0.0.205 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player for chrome
  version 23.0.0.205 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb16-36.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_flash_player_within_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Chrome/Lin/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!playerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: playerVer, test_version: "23.0.0.205" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "23.0.0.205" );
	security_message( data: report );
	exit( 0 );
}

