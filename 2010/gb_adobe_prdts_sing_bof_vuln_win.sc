if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801515" );
	script_version( "2020-05-28T14:41:23+0000" );
	script_cve_id( "CVE-2010-2883" );
	script_bugtraq_id( 43057 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)" );
	script_name( "Adobe Acrobat and Reader SING 'uniqueName' Buffer Overflow Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader/Acrobat and is prone to buffer
  overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error within 'CoolType.dll' when processing the
  'uniqueName' entry of SING tables in fonts." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to crash an affected application
  or execute arbitrary code by tricking a user into opening a specially crafted PDF document." );
	script_tag( name: "affected", value: "Adobe Reader version 9.3.4 and prior.

  Adobe Acrobat version 9.3.4 and prior on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader/Adobe Acrobat version 9.4 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41340" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa10-02.html" );
	script_xref( name: "URL", value: "http://blog.metasploit.com/2010/09/return-of-unpublished-adobe.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
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
if(version_is_less_equal( version: vers, test_version: "9.3.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

