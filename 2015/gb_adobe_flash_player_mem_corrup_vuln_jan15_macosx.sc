CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805257" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-0310" );
	script_bugtraq_id( 72261 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-01-27 15:46:43 +0530 (Tue, 27 Jan 2015)" );
	script_name( "Adobe Flash Player Unspecified Memory Corruption Vulnerability - Jan15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to unspecified memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to bypass certain security restrictions and potentially conduct
  more severe attacks." );
	script_tag( name: "affected", value: "Adobe Flash Player version 13.x before
  13.0.0.262 and 14.x through 16.x before 16.0.0.287 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  13.0.0.262 or 16.0.0.287 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62452" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb15-02.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Flash/Player/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!playerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: playerVer, test_version: "13.0", test_version2: "13.0.0.261" ) || version_in_range( version: playerVer, test_version: "14.0.0", test_version2: "16.0.0.286" )){
	if( IsMatchRegexp( playerVer, "^13\\." ) ){
		fix = "13.0.0.262";
	}
	else {
		fix = "16.0.0.287";
	}
	report = "Installed version: " + playerVer + "\n" + "Fixed version:     " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

