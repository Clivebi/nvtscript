CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805004" );
	script_version( "2021-08-11T09:52:19+0000" );
	script_cve_id( "CVE-2014-0558", "CVE-2014-0564", "CVE-2014-0569", "CVE-2014-8439" );
	script_bugtraq_id( 70437, 70442, 70441, 71289 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 09:52:19 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-10-20 12:43:30 +0530 (Mon, 20 Oct 2014)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities(APSB14-22)-(Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Two unspecified errors can be exploited to corrupt memory and subsequently
    execute arbitrary code.

  - An integer overflow error can be exploited to execute arbitrary code." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Flash Player before 11.2.202.411
  on Linux" );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  11.2.202.411 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59729" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-22.html" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.411" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "11.2.202.411" );
	security_message( port: 0, data: report );
	exit( 0 );
}

