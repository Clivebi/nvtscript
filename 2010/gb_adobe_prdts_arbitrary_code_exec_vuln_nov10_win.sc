if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801477" );
	script_version( "2020-05-28T14:41:23+0000" );
	script_tag( name: "last_modification", value: "2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2010-11-10 14:58:25 +0100 (Wed, 10 Nov 2010)" );
	script_cve_id( "CVE-2010-3654" );
	script_bugtraq_id( 44504 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Products Content Code Execution Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41917" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/298081" );
	script_xref( name: "URL", value: "http://contagiodump.blogspot.com/2010/10/potential-new-adobe-flash-player-zero.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc", "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary
  code in the context of the user running the affected application." );
	script_tag( name: "affected", value: "Adobe Reader/Acrobat version 9.x to 9.4 on Windows
  Adobe Flash Player version 10.1.85.3 and prior on Windows" );
	script_tag( name: "insight", value: "The flaw is caused by an unspecified error which can be
  exploited to execute arbitrary code." );
	script_tag( name: "summary", value: "This host has Adobe Acrobat or Adobe Reader or Adobe flash Player
  installed, and is prone to arbitrary code execution vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.1.102.64 or later

  Upgrade to Adobe Reader/Acrobat version 9.4.1 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:acrobat_reader",
	 "cpe:/a:adobe:acrobat",
	 "cpe:/a:adobe:flash_player" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( cpe == "cpe:/a:adobe:acrobat_reader" || cpe == "cpe:/a:adobe:acrobat" ){
	if(version_in_range( version: vers, test_version: "9.0.0", test_version2: "9.4" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "9.0.0 - 9.4", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(cpe == "cpe:/a:adobe:flash_player"){
		if(version_is_less_equal( version: vers, test_version: "10.1.85.3" )){
			report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 10.1.85.3", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

