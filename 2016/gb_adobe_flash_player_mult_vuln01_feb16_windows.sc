CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806865" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2016-0964", "CVE-2016-0965", "CVE-2016-0966", "CVE-2016-0967", "CVE-2016-0968", "CVE-2016-0969", "CVE-2016-0970", "CVE-2016-0971", "CVE-2016-0972", "CVE-2016-0973", "CVE-2016-0974", "CVE-2016-0975", "CVE-2016-0976", "CVE-2016-0977", "CVE-2016-0978", "CVE-2016-0979", "CVE-2016-0980", "CVE-2016-0981", "CVE-2016-0982", "CVE-2016-0983", "CVE-2016-0984", "CVE-2016-0985" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-10 01:29:00 +0000 (Sun, 10 Sep 2017)" );
	script_tag( name: "creation_date", value: "2016-02-10 13:23:06 +0530 (Wed, 10 Feb 2016)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities -01 Feb16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple memory corruption vulnerabilities

  - Multiple use-after-free vulnerabilities

  - A heap buffer overflow vulnerability

  - A type confusion vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will
  potentially allow an attacker to execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  18.0.0.329 and 19.x and 20.x before 20.0.0.306 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  18.0.0.329 or 20.0.0.306 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb16-04.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if( version_in_range( version: playerVer, test_version: "19.0", test_version2: "20.0.0.305" ) ){
	fix = "20.0.0.306";
	VULN = TRUE;
}
else {
	if(version_is_less( version: playerVer, test_version: "18.0.0.329" )){
		fix = "18.0.0.329";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

