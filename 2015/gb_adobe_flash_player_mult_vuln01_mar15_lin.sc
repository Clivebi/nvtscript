CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805493" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-0342", "CVE-2015-0341", "CVE-2015-0340", "CVE-2015-0339", "CVE-2015-0338", "CVE-2015-0337", "CVE-2015-0336", "CVE-2015-0335", "CVE-2015-0334", "CVE-2015-0333", "CVE-2015-0332" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-03-17 09:58:58 +0530 (Tue, 17 Mar 2015)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities - 01 Mar15 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple unspecified use-after-free errors.

  - Multiple unspecified errors due to improper validation of user-supplied input.

  - Multiple unspecified type confusion errors.

  - Integer overflow in adobe Flash Player." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause denial of service execute arbitrary code, bypass intended
  file-upload restrictions or have other unspecified impacts." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  11.2.202.451 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  11.2.202.451 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb15-05.html" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.451" )){
	fix = "11.2.202.451";
	VULN = TRUE;
}
if(VULN){
	report = "Installed version: " + playerVer + "\n" + "Fixed version:     " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

