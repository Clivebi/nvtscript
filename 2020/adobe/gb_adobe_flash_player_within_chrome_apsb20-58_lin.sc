CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817803" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-9746" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-21 12:06:00 +0000 (Wed, 21 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-14 18:03:31 +0530 (Wed, 14 Oct 2020)" );
	script_name( "Adobe Flash Player Within Google Chrome Security Update (APSB20-58) - Linux" );
	script_tag( name: "summary", value: "Adobe Flash Player is prone to an arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a null pointer
  dereference error." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Flash Player prior to 32.0.0.445
  within Google Chrome." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player for Google Chrome
  32.0.0.445 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb20-58.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_flash_player_within_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Chrome/Lin/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "32.0.0.445" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "32.0.0.445", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

