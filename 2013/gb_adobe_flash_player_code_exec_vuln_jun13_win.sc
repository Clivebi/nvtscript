CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803661" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2013-3343" );
	script_bugtraq_id( 60478 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2013-06-18 13:23:17 +0530 (Tue, 18 Jun 2013)" );
	script_name( "Adobe Flash Player Remote Code Execution Vulnerability -June13 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53751" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-16.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe Flash Player version 10.3.183.86 and earlier and 11.x to 11.7.700.202
  on Windows" );
	script_tag( name: "insight", value: "Unspecified flaw due to improper sanitization of user-supplied input." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player 10.3.183.90 or 11.7.700.224 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  remote code execution vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "10.3.183.86" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.7.700.202" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.3.183.90 or 11.7.700.224", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );
