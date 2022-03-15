CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804516" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-0503", "CVE-2014-0504" );
	script_bugtraq_id( 66122, 66127 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-03-20 10:54:21 +0530 (Thu, 20 Mar 2014)" );
	script_name( "Adobe Flash Player Multiple Security Bypass Vulnerabilities - 01 Feb14 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to multiple
security bypass vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw are due to multiple unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
restrictions and disclose potentially sensitive information." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 11.2.202.346 on Linux." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.2.202.346 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57271" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-08.html" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.346" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "11.2.202.346" );
	security_message( port: 0, data: report );
	exit( 0 );
}

