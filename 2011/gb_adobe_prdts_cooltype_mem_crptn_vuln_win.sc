if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801933" );
	script_version( "2020-05-28T14:41:23+0000" );
	script_cve_id( "CVE-2011-0610" );
	script_bugtraq_id( 47531 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)" );
	script_name( "Adobe Reader and Acrobat 'CoolType.dll' Memory Corruption Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader/Acrobat and is prone to memory
  corruption and reemote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "This issue is caused by a memory corruption error in the 'CoolType' library
  when processing the malformed Flash content within a PDF document." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to crash an affected application
  or compromise a vulnerable system by tricking a user into opening a specially crafted PDF file." );
	script_tag( name: "affected", value: "Adobe Reader version prior to 9.4.4 and 10.x to 10.0.1

  Adobe Acrobat version prior to 9.4.4 and 10.x to 10.0.2 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.4.4 or Acrobat 9.4.4 or 10.0.3.

  NOTE : No fix available for Adobe Reader X (10.x), vendors are planning to
         address this issue in next quarterly security update for Adobe Reader." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0923" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-08.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:acrobat_reader",
	 "cpe:/a:adobe:acrobat" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( cpe == "cpe:/a:adobe:acrobat_reader" ){
	if(version_is_less( version: vers, test_version: "9.4.4" ) || version_in_range( version: vers, test_version: "10.0", test_version2: "10.0.1" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "9.4.4. For 10.x see the references.", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(cpe == "cpe:/a:adobe:acrobat"){
		if(version_is_less( version: vers, test_version: "9.4.4" ) || version_in_range( version: vers, test_version: "10.0", test_version2: "10.0.2" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "9.4.4 or 10.0.3", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

