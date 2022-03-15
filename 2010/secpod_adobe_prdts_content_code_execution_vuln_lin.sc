if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902304" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_cve_id( "CVE-2010-2884" );
	script_bugtraq_id( 43205 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)" );
	script_name( "Adobe Reader/Flash Player Content Code Execution Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader/Flash player and is prone to Content
Code Execution Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is caused by an unspecified error when processing malformed 'Flash'
or '3D' and 'Multimedia' content within a PDF document, which could be
exploited by attackers to execute arbitrary code by convincing a user to open
a specially crafted PDF file." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to corrupt memory and execute
arbitrary code on the system with elevated privileges." );
	script_tag( name: "affected", value: "Adobe Reader version 9.3.4 and before on Linux.
Adobe Flash Player version 10.1.82.76 and before on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash version 10.1.85.3 or later and Adobe Reader version 9.4
or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61771" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2349" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2348" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa10-03.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc", "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader/Linux/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:adobe:acrobat_reader";
if(vers = get_app_version( cpe: CPE )){
	if(version_is_less_equal( version: vers, test_version: "9.3.4" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 9.3.4" );
		security_message( port: 0, data: report );
	}
}
vers = get_kb_item( "AdobeFlashPlayer/Linux/Ver" );
vers = ereg_replace( pattern: ",", string: vers, replace: "." );
if(!vers){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "10.1.82.76" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 10.1.82.76" );
	security_message( port: 0, data: report );
}

