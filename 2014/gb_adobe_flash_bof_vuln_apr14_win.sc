CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804559" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2014-0515" );
	script_bugtraq_id( 67092 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2014-04-29 11:45:09 +0530 (Tue, 29 Apr 2014)" );
	script_name( "Adobe Flash Player Buffer Overflow Vulnerability - Apr14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to buffer
overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to an improper validation of user-supplied input to the pixel
bender component." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code and
cause a buffer overflow, resulting in a denial of service condition." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 11.7.700.279 and 11.8.x through 13.0.x
before 13.0.0.206 on Windows" );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.7.700.279 or 13.0.0.206 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=2577" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/blog/8212" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-13.html" );
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
if(version_is_less( version: playerVer, test_version: "11.7.700.279" ) || version_in_range( version: playerVer, test_version: "11.8.0", test_version2: "13.0.0.205" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

