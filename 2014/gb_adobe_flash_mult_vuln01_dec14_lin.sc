CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805214" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-0580", "CVE-2014-0587", "CVE-2014-8443", "CVE-2014-9162", "CVE-2014-9164", "CVE-2014-9163" );
	script_bugtraq_id( 71584, 71586, 71585, 71581, 71583, 71582 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-12-15 17:56:26 +0530 (Mon, 15 Dec 2014)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities(APSB14-27)- 01 Dec14 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An out-of-bounds read error when handling Regular Expression Objects.

  - Some unspecified errors.

  - A use-after-free error.

  - An error when the 'parseFloat' function is called on a specific datatype." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to disclose potentially sensitive information, bypass certain security
  restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  11.2.202.425 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  11.2.202.425 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/61094" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-27.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.425" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "11.2.202.425" );
	security_message( port: 0, data: report );
	exit( 0 );
}

