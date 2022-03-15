CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805918" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-5122", "CVE-2015-5123" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-07-13 10:55:22 +0530 (Mon, 13 Jul 2015)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities -01 July15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An use-after-free error triggered by freeing a TextLine object within the
  'valueOf' function of a custom class when setting the TextLine's
  opaqueBackground.

  - An unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack and potentially execute arbitrary
  code in the context of the affected user." );
	script_tag( name: "affected", value: "Adobe Flash Player version 13.0.0.302 and
  prior, and 14.x through 18.0.0.203 versions on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  18.0.0.209 or 13.0.0.305 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsa15-04.html" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb15-18.html" );
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
if(version_is_less_equal( version: playerVer, test_version: "13.0.0.302" )){
	fix = "13.0.0.305";
	VULN = TRUE;
}
if(version_in_range( version: playerVer, test_version: "14.0", test_version2: "18.0.0.203" )){
	fix = "18.0.0.209";
	VULN = TRUE;
}
if(VULN){
	report = "Installed version: " + playerVer + "\n" + "Fixed version:     " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

