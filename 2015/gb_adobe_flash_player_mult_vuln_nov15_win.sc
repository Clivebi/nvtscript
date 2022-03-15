CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806616" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-7651", "CVE-2015-7652", "CVE-2015-7653", "CVE-2015-7654", "CVE-2015-7655", "CVE-2015-7656", "CVE-2015-7657", "CVE-2015-7658", "CVE-2015-7659", "CVE-2015-7660", "CVE-2015-7661", "CVE-2015-7662", "CVE-2015-7663", "CVE-2015-8042", "CVE-2015-8043", "CVE-2015-8044", "CVE-2015-8046" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-11-13 17:36:09 +0530 (Fri, 13 Nov 2015)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities Nov15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A type confusion error.

  - Multiple use-after-free errors.

  - Another unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to bypass security restrictions and execute arbitrary code on the affected
  system." );
	script_tag( name: "affected", value: "Adobe Flash Player version 18.x before
  18.0.0.261 and 19.x before 19.0.0.245 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  18.0.0.261 or 19.0.0.245 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb15-28.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if( version_in_range( version: playerVer, test_version: "19.0", test_version2: "19.0.0.244" ) ){
	fix = "19.0.0.245";
	VULN = TRUE;
}
else {
	if(version_in_range( version: playerVer, test_version: "18.0", test_version2: "18.0.0.260" )){
		fix = "18.0.0.261";
		VULN = TRUE;
	}
}
if(VULN){
	report = "Installed version: " + playerVer + "\n" + "Fixed version:" + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

