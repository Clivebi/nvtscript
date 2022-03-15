CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804538" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-0507", "CVE-2014-0508", "CVE-2014-0509" );
	script_bugtraq_id( 66701, 66699, 66703 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-11 13:09:05 +0530 (Fri, 11 Apr 2014)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities - 02 Apr14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error related to regular expressions in ActionScript.

  - An use-after-free error and multiple unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct cross-site scripting
attacks, bypass certain security restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 11.7.700.275 and 11.8.x through 13.0.x
before 13.0.0.182 on Mac OS X" );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.7.700.275 or 13.0.0.182 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57661" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-09.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(version_is_less( version: playerVer, test_version: "11.7.700.275" ) || version_in_range( version: playerVer, test_version: "11.8.0", test_version2: "13.0.0.181" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

