CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805261" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-0311", "CVE-2015-0312" );
	script_bugtraq_id( 72283, 72343 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-01-27 16:19:35 +0530 (Tue, 27 Jan 2015)" );
	script_name( "Adobe Flash Player Unspecified Code Execution Vulnerability - Jan15 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to unspecified arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error and double-free flaw that is triggered as user-supplied input is not
  properly validated." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Flash Player through version
  11.2.202.438 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  11.2.202.440 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62432" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsa15-01.html" );
	script_xref( name: "URL", value: "http://www.rapid7.com/db/vulnerabilities/adobe-flash-apsb15-03-cve-2015-0312" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.440" )){
	report = "Installed version: " + playerVer + "\n" + "Fixed version:     11.2.202.440\n";
	security_message( data: report );
	exit( 0 );
}

