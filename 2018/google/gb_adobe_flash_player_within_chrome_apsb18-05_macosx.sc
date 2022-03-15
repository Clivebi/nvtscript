CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813028" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_cve_id( "CVE-2018-4920", "CVE-2018-4919" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-27 13:39:00 +0000 (Wed, 27 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-03-14 11:17:28 +0530 (Wed, 14 Mar 2018)" );
	script_name( "Adobe Flash Player Within Google Chrome Multiple RCE Vulnerabilities - Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple remote code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to a type confusion
  error and use-after-free error in the flash player." );
	script_tag( name: "impact", value: "Successful exploitation of these vulnerabilities
  will allow an attacker to execute arbitrary code on affected system and take
  control of the affected system." );
	script_tag( name: "affected", value: "Adobe Flash Player version 28.0.0.161 and
  earlier within Google Chrome on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  29.0.0.113 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb18-05.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_is_less_equal( version: vers, test_version: "28.0.0.161" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "29.0.0.113", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

