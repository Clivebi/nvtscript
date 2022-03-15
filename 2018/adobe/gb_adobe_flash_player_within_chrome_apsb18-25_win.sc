CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813832" );
	script_version( "2021-05-31T06:00:15+0200" );
	script_cve_id( "CVE-2018-12824", "CVE-2018-12825", "CVE-2018-12826", "CVE-2018-12827", "CVE-2018-12828" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:15 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-08-15 09:37:06 +0530 (Wed, 15 Aug 2018)" );
	script_name( "Adobe Flash Player Within Google Chrome Security Update(apsb18-25)- Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple out-of-bounds read errors.

  - Use of a component with a known vulnerability.

  - An unknown security bypass vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to escalate privileges, disclose sensitive information and bypass
  security restrictions." );
	script_tag( name: "affected", value: "Adobe Flash Player prior to 30.0.0.154
  within Google Chrome on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player for
  Google Chrome 30.0.0.154, or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb18-25.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "30.0.0.154" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "30.0.0.154", install_path: path );
	security_message( data: report );
	exit( 0 );
}

