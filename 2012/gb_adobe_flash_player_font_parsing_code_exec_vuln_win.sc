CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802940" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-1535" );
	script_bugtraq_id( 55009 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-08-20 13:00:42 +0530 (Mon, 20 Aug 2012)" );
	script_name( "Adobe Flash Player Font Parsing Code Execution Vulnerability - (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50285/" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-18.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code or
  cause the application to crash and take control of the affected system." );
	script_tag( name: "affected", value: "Adobe Flash Player version prior to 11.3.300.271 on Windows" );
	script_tag( name: "insight", value: "An unspecified error occurs when handling SWF content in a word document.
  This may allow a context-dependent attacker to execute arbitrary code." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 11.3.300.271 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  unspecified code execution vulnerability." );
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
if(version_is_less( version: vers, test_version: "11.3.300.271" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.3.300.271", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

