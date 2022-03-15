CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810843" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2017-3058", "CVE-2017-3059", "CVE-2017-3060", "CVE-2017-3061", "CVE-2017-3062", "CVE-2017-3063", "CVE-2017-3064", "CVE-2015-5122", "CVE-2015-5123" );
	script_bugtraq_id( 97551, 97557, 75712, 75710 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-04-12 10:07:04 +0530 (Wed, 12 Apr 2017)" );
	script_name( "Adobe Flash Player Within Google Chrome Security Update (apsb17-07) - Linux" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use-after-free vulnerabilities that could lead to code execution.

  - Memory corruption vulnerabilities that could lead to code execution." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code on
  the target user's system and that could potentially allow an attacker to
  take control of the affected system." );
	script_tag( name: "affected", value: "Adobe Flash Player for chrome versions
  before 25.0.0.127 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player for chrome
  25.0.0.148, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb17-10.html" );
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
if(version_is_less( version: playerVer, test_version: "25.0.0.148" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "25.0.0.148" );
	security_message( data: report );
	exit( 0 );
}

