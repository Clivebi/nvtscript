CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803152" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2013-0630" );
	script_bugtraq_id( 57184 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2013-01-15 15:38:40 +0530 (Tue, 15 Jan 2013)" );
	script_name( "Adobe Flash Player Buffer Overflow Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51771" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027950" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-01.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial of service condition." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 10.3.183.50, 11.x before 11.5.502.146 on Windows" );
	script_tag( name: "insight", value: "An integer overflow error within 'flash.display.BitmapData()', which can be
  exploited to cause a heap-based buffer overflow." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 10.3.183.50 or 11.5.502.146 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  buffer overflow vulnerability." );
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
if(version_is_less( version: vers, test_version: "10.3.183.50" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.5.502.145" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "10.3.183.50 or 11.5.502.146", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

