CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804590" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-0516", "CVE-2014-0517", "CVE-2014-0518", "CVE-2014-0519", "CVE-2014-0520" );
	script_bugtraq_id( 67361, 67364, 67371, 67373, 67372 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-05-22 12:59:42 +0530 (Thu, 22 May 2014)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities - May14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to an use-after free error when handling display
objects and multiple unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 13.0.0.214 on Mac OS X" );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 13.0.0.214 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/58074" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-14.html" );
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
if(version_is_less( version: playerVer, test_version: "13.0.0.214" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "13.0.0.214" );
	security_message( port: 0, data: report );
	exit( 0 );
}

