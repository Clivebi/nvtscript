CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805211" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2014-9163" );
	script_bugtraq_id( 71582 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2014-12-15 17:48:41 +0530 (Mon, 15 Dec 2014)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities(APSB14-27)- 02 Dec14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when the
  'parseFloat' function is called on a specific datatype." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause a stack-based buffer overflow, potentially allowing the execution of
  arbitrary code." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  13.0.0.259, 14.x and 15.x before 15.0.0.246 and 16.x before 16.0.0.235 on
  Windows" );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  13.0.0.259 or 15.0.0.246 or 16.0.0.235 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/61094" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-27.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!playerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: playerVer, test_version: "13.0.0.259" ) || version_in_range( version: playerVer, test_version: "14.0.0", test_version2: "15.0.0.245" ) || version_in_range( version: playerVer, test_version: "16.0.0", test_version2: "16.0.0.234" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

