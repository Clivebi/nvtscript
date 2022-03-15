CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804065" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-0491", "CVE-2014-0492" );
	script_bugtraq_id( 64807, 64810 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-01-21 11:10:22 +0530 (Tue, 21 Jan 2014)" );
	script_name( "Adobe Flash Player Security Bypass Vulnerability Jan14 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to security bypass
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to an unspecified error and other additional weakness." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to, bypass certain security
restrictions and disclose certain memory information." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 11.2.202.335 on Linux." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.2.202.335 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56267" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-02.html" );
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
if(version_is_less( version: playerVer, test_version: "11.2.202.335" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "11.2.202.335" );
	security_message( port: 0, data: report );
	exit( 0 );
}

