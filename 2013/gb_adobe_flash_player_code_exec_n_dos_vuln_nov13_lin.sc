CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804147" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-5329", "CVE-2013-5330" );
	script_bugtraq_id( 63680, 63680 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-11-19 16:31:55 +0530 (Tue, 19 Nov 2013)" );
	script_name( "Adobe Flash Player Code Execution and DoS Vulnerabilities Nov13 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to remote code
execution and denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.2.202.327 or later." );
	script_tag( name: "insight", value: "Flaws are due to unspecified errors." );
	script_tag( name: "affected", value: "Adobe Flash Player before version 11.2.202.327 on Linux" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code, cause
denial of service (memory corruption) and compromise a user's system." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55527" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-26.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.327" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "11.2.202.327" );
	security_message( port: 0, data: report );
	exit( 0 );
}

