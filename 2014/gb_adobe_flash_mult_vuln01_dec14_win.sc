CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805210" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-0580", "CVE-2014-0587", "CVE-2014-8443", "CVE-2014-9162", "CVE-2014-9164" );
	script_bugtraq_id( 71584, 71586, 71585, 71581, 71583 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-12-15 17:08:41 +0530 (Mon, 15 Dec 2014)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities(APSB14-27)- 01 Dec14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An out-of-bounds read error when handling Regular Expression Objects.

  - Some unspecified errors.

  - A use-after-free error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to disclose potentially sensitive information, bypass certain security
  restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  13.0.0.259, 14.x through 16.x before 16.0.0.235 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  13.0.0.259 or 16.0.0.235 or later." );
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
if(version_is_less( version: playerVer, test_version: "13.0.0.259" ) || version_in_range( version: playerVer, test_version: "14.0.0", test_version2: "16.0.0.234" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

