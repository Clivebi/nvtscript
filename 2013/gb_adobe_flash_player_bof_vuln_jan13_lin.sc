if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803154" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2013-0630" );
	script_bugtraq_id( 57184 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2013-01-15 16:09:23 +0530 (Tue, 15 Jan 2013)" );
	script_name( "Adobe Flash Player Buffer Overflow Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51771" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027950" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-01.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial of service condition." );
	script_tag( name: "insight", value: "An integer overflow error within 'flash.display.BitmapData()', which can be
  exploited to cause a heap-based buffer overflow." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  buffer overflow vulnerability." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 10.3.183.50, 11.x before 11.2.202.261 on Linux

  Update to Adobe Flash Player version 10.3.183.50 or 11.2.202.261 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
playerVer = get_kb_item( "AdobeFlashPlayer/Linux/Ver" );
if(playerVer && IsMatchRegexp( playerVer, "," )){
	playerVer = ereg_replace( pattern: ",", string: playerVer, replace: "." );
}
if(playerVer){
	if(version_is_less( version: playerVer, test_version: "10.3.183.50" ) || version_in_range( version: playerVer, test_version: "11.0", test_version2: "11.2.202.260" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
