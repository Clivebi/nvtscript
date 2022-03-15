CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804716" );
	script_version( "2021-08-11T09:52:19+0000" );
	script_cve_id( "CVE-2014-4671", "CVE-2014-0539", "CVE-2014-0537" );
	script_bugtraq_id( 68457, 68454, 68455 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-11 09:52:19 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-07-11 10:58:35 +0530 (Fri, 11 Jul 2014)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities-01 July14 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error when handling JSONP callbacks.

  - Multiple Unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
restrictions." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 11.2.202.394 on Linux." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.2.202.394 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59774" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-17.html" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.394" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "11.2.202.394" );
	security_message( port: 0, data: report );
	exit( 0 );
}

