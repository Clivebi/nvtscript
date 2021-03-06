CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805258" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-0310" );
	script_bugtraq_id( 72261 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-01-27 15:48:12 +0530 (Tue, 27 Jan 2015)" );
	script_name( "Adobe Flash Player Unspecified Memory Corruption Vulnerability - Jan15 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to unspecified memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to bypass certain security restrictions and potentially conduct
  more severe attacks." );
	script_tag( name: "affected", value: "Adobe Flash Player before version
  11.2.202.438 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  11.2.202.438 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62452" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb15-02.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!playerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: playerVer, test_version: "11.2.202.438" )){
	report = "Installed version: " + playerVer + "\n" + "Fixed version:     11.2.202.438\n";
	security_message( data: report );
	exit( 0 );
}

