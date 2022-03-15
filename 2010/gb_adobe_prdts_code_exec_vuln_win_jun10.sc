if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801360" );
	script_version( "2020-05-28T14:41:23+0000" );
	script_tag( name: "last_modification", value: "2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)" );
	script_cve_id( "CVE-2010-1297" );
	script_bugtraq_id( 40586 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Products Remote Code Execution Vulnerability - jun10 (Windows)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1349" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1348" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa10-01.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc", "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary code by tricking a user into opening a specially crafted PDF file." );
	script_tag( name: "affected", value: "Adobe Reader/Acrobat version 9.x to 9.3.2

  Adobe Flash Player version 9.0.x to 9.0.262 and 10.x to 10.0.45.2" );
	script_tag( name: "insight", value: "The flaw is due to a memory corruption error in the 'authplay.dll'
  library and 'SWF' file when processing ActionScript Virtual Machine 2 (AVM2)
  'newfunction' instructions within Flash content in a PDF document." );
	script_tag( name: "summary", value: "This host is installed with Adobe products and is prone to
  remote code execution vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to Adobe Flash Player 10.1.53.64 or 9.0.277.0 or later

  For Adobe Reader additional updates has been released which are described in the referenced advisories." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:flash_player",
	 "cpe:/a:adobe:acrobat",
	 "cpe:/a:adobe:acrobat_reader" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( cpe == "cpe:/a:adobe:flash_player" ){
	if(version_in_range( version: vers, test_version: "9.0.0", test_version2: "9.0.262" ) || version_in_range( version: vers, test_version: "10.0", test_version2: "10.0.45.2" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "10.1.53.64 or 9.0.277.0", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(cpe == "cpe:/a:adobe:acrobat" || cpe == "cpe:/a:adobe:acrobat_reader"){
		if(version_in_range( version: vers, test_version: "9.0", test_version2: "9.3.2" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

