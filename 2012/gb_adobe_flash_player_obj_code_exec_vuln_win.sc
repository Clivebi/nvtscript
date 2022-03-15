CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802772" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0779" );
	script_bugtraq_id( 53395 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-05-08 13:53:41 +0530 (Tue, 08 May 2012)" );
	script_name( "Adobe Flash Player Object Confusion Remote Code Execution Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49096/" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027023" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-09.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to create crafted Flash content
  that, when loaded by the target user, will trigger an object confusion flaw
  and execute arbitrary code on the target system." );
	script_tag( name: "affected", value: "Adobe Flash Player version prior to 10.3.183.19 on Windows
  Adobe Flash Player version 11.x prior to 11.2.202.235 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.3.183.19 or 11.2.202.235 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  object confusion remote code execution vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to an error related to object confusion.

  NOTE: Further information is not available." );
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
if(version_is_less( version: vers, test_version: "10.3.183.19" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.2.202.233" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.3.183.19 or 11.2.202.235", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

