if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902750" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-2445", "CVE-2011-2450", "CVE-2011-2451", "CVE-2011-2452", "CVE-2011-2453", "CVE-2011-2454", "CVE-2011-2455", "CVE-2011-2456", "CVE-2011-2457", "CVE-2011-2458", "CVE-2011-2459", "CVE-2011-2460" );
	script_bugtraq_id( 50625, 50619, 50623, 50622, 50618, 50626, 50627, 50624, 50621, 50629, 50620, 50628 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-16 11:45:29 +0530 (Wed, 16 Nov 2011)" );
	script_name( "Adobe Flash Player/Air Multiple Vulnerabilities - November 11 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46818/" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-28.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe AIR version prior to 3.1.0.4880 on Windows

  Adobe Flash Player version prior to 10.3.183.11 and 11.x through 11.0.1.152 on Windows." );
	script_tag( name: "insight", value: "The flaws are due to memory corruption, heap corruption, buffer
  overflow, stack overflow errors that could lead to code execution." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities." );
	script_tag( name: "solution", value: "Update to Adobe Air version 3.1.0.4880 or later

  Update to Adobe Flash Player version 10.3.183.11 or 11.1.102.55 or later" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:flash_player",
	 "cpe:/a:adobe:adobe_air" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( cpe == "cpe:/a:adobe:flash_player" ){
	if(version_is_less( version: vers, test_version: "10.3.183.11" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.0.1.152" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "10.3.183.11 or 11.1.102.55", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(cpe == "cpe:/a:adobe:adobe_air"){
		if(version_is_less( version: vers, test_version: "3.1.0.4880" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.0.4880", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

