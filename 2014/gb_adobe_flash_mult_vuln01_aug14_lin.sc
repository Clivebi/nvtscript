CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804744" );
	script_version( "2021-08-11T09:52:19+0000" );
	script_cve_id( "CVE-2014-0538", "CVE-2014-0540", "CVE-2014-0541", "CVE-2014-0542", "CVE-2014-0543", "CVE-2014-0544", "CVE-2014-0545", "CVE-2014-5333" );
	script_bugtraq_id( 69192, 69190, 69191, 69194, 69195, 69196, 69197, 69320 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 09:52:19 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-08-19 14:45:04 +0530 (Tue, 19 Aug 2014)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities-01 Aug14 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to an unspecified error and an use-after-free error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Flash Player version 11.2.202.400 on Linux" );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.2.202.400 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/58593" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-18.html" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.400" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "11.2.202.400" );
	security_message( port: 0, data: report );
	exit( 0 );
}

