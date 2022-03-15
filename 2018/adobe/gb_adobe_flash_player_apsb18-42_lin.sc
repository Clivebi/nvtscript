CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814525" );
	script_version( "2021-06-01T06:00:13+0200" );
	script_cve_id( "CVE-2018-15982", "CVE-2018-15983" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-01 06:00:13 +0200 (Tue, 01 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-29 19:24:00 +0000 (Tue, 29 Jan 2019)" );
	script_tag( name: "creation_date", value: "2018-12-06 11:21:11 +0530 (Thu, 06 Dec 2018)" );
	script_name( "Adobe Flash Player Security Updates(apsb18-42)-Linux" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to insecure
  library loading (DLL hijacking) and use after free vulnerabilities in Adobe
  Flash Player" );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code and escalate privileges
  on the vulnerable system." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 32.0.0.101
  on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player 32.0.0.101,
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb18-42.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "32.0.0.101" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "32.0.0.101", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

