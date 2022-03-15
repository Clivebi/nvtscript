CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804167" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2013-5331", "CVE-2013-5332" );
	script_bugtraq_id( 64199, 64201 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2013-12-18 16:07:12 +0530 (Wed, 18 Dec 2013)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities-01 Dec13 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.7.700.257 or 11.9.900.170 or later." );
	script_tag( name: "insight", value: "Flaws are due to multiple unspecified errors." );
	script_tag( name: "affected", value: "Adobe Flash Player before version 11.7.700.257, 11.8.x, 11.9.x before
11.9.900.170 on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption(denial of service) and compromise a user's system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55948" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb13-28.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
if(version_is_less( version: playerVer, test_version: "11.7.700.257" ) || version_in_range( version: playerVer, test_version: "11.8.0", test_version2: "11.9.900.169" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

