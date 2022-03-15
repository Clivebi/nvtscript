if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802206" );
	script_version( "2020-05-28T14:41:23+0000" );
	script_cve_id( "CVE-2011-2107" );
	script_bugtraq_id( 48107 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_name( "Adobe Products Unspecified Cross-Site Scripting Vulnerability June-2011 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player, Adobe Reader or Acrobat and is
  prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of certain unspecified input, which
  allows remote attackers to inject arbitrary web script or HTML via unspecified vectors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site." );
	script_tag( name: "affected", value: "Adobe Flash Player versions prior to 10.3.181.22 on Windows.

  Adobe Reader and Acrobat X versions 10.0.3 and prior on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.3.181.22 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-13.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc", "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:flash_player",
	 "cpe:/a:adobe:acrobat_reader",
	 "cpe:/a:adobe:acrobat" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( cpe == "cpe:/a:adobe:flash_player" ){
	if(version_is_less( version: vers, test_version: "10.3.181.22" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "10.3.181.22", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(cpe == "cpe:/a:adobe:acrobat_reader" || cpe == "cpe:/a:adobe:acrobat"){
		if(version_is_less_equal( version: vers, test_version: "10.0.3" )){
			report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 10.0.3", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

