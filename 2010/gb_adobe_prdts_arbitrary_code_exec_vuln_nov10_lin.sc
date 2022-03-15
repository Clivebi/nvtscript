if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801478" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-11-10 14:58:25 +0100 (Wed, 10 Nov 2010)" );
	script_cve_id( "CVE-2010-3654" );
	script_bugtraq_id( 44504 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Products Content Code Execution Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41917" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/298081" );
	script_xref( name: "URL", value: "http://contagiodump.blogspot.com/2010/10/potential-new-adobe-flash-player-zero.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc", "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader/Linux/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary
  code in the context of the user running the affected application." );
	script_tag( name: "affected", value: "Adobe Reader/Acrobat version 9.x to 9.4 on Linux
  Adobe Flash Player version 10.1.85.3 and prior on Linux" );
	script_tag( name: "insight", value: "The flaw is caused by an unspecified error which can be exploited
  to execute arbitrary code." );
	script_tag( name: "summary", value: "This host has Adobe Acrobat or Adobe Reader or Adobe flash Player
  installed, and is prone to arbitrary code execution vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.1.102.64 or later

  Upgrade to Adobe Reader/Acrobat version 9.4.1 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
readerVer = get_kb_item( "Adobe/Reader/Linux/Version" );
if(readerVer){
	if(version_in_range( version: readerVer, test_version: "9.0.0", test_version2: "9.4" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "9.0.0 - 9.4" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
flashVer = get_kb_item( "AdobeFlashPlayer/Linux/Ver" );
flashVer = ereg_replace( pattern: ",", string: flashVer, replace: "." );
if(flashVer){
	if(version_is_less_equal( version: flashVer, test_version: "10.1.85.3" )){
		report = report_fixed_ver( installed_version: flashVer, vulnerable_range: "Less than or equal to 10.1.85.3" );
		security_message( port: 0, data: report );
	}
}

