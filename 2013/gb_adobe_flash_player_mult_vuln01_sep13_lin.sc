CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803899" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-5324", "CVE-2013-3361", "CVE-2013-3362", "CVE-2013-3363" );
	script_bugtraq_id( 62296, 62290, 62294, 62295 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 19:01:01 +0530 (Wed, 18 Sep 2013)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities-01 Sep13 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.2.202.310 or later." );
	script_tag( name: "insight", value: "Flaws are due to multiple unspecified errors." );
	script_tag( name: "affected", value: "Adobe Flash Player before 11.2.202.310 on Linux" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption and compromise a user's system." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54697/" );
	script_xref( name: "URL", value: "https://www.adobe.com/support/security/bulletins/apsb13-21.html" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.310" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "11.2.202.310" );
	security_message( port: 0, data: report );
	exit( 0 );
}

