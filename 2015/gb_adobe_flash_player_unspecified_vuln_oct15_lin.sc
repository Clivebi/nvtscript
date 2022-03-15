CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806500" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-7645", "CVE-2015-7647", "CVE-2015-7648" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-10-16 15:46:37 +0530 (Fri, 16 Oct 2015)" );
	script_name( "Adobe Flash Player Unspecified Vulnerability Oct15 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to some unspecified
  critical vulnerabilities in Adobe Flash Player." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause a crash and potentially an attacker to take control of the affected
  system." );
	script_tag( name: "affected", value: "Adobe Flash Player versions 11.x through
  11.2.202.535 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  11.2.202.540 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsa15-05.html" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb15-27.html" );
	script_xref( name: "URL", value: "http://blog.trendmicro.com/trendlabs-security-intelligence/new-adobe-flash-zero-day-used-in-pawn-storm-campaign" );
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
if(version_in_range( version: playerVer, test_version: "11.0", test_version2: "11.2.202.535" )){
	report = "Installed version: " + playerVer + "\n" + "Fixed version:  11.2.202.540 \n";
	security_message( data: report );
	exit( 0 );
}

