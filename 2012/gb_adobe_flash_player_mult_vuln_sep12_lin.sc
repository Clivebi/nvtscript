if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803024" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-4163", "CVE-2012-4164", "CVE-2012-4165", "CVE-2012-4166", "CVE-2012-4167", "CVE-2012-4168", "CVE-2012-4171", "CVE-2012-5054" );
	script_bugtraq_id( 55136, 55365 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-09-03 16:55:27 +0530 (Mon, 03 Sep 2012)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities - Sep12 (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50354/" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-19.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 10.3.183.23, 11.x before 11.2.202.238 on Linux" );
	script_tag( name: "insight", value: "- Multiple errors due to memory corruption, integer overflow that
    could lead to code execution.

  - A logic error due to improper handling of multiple dialogs in Firefox
    allows attackers to crash the application." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 10.3.183.23 or 11.4.402.265 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "AdobeFlashPlayer/Linux/Ver" );
if(vers && ContainsString( vers, "," )){
	vers = ereg_replace( pattern: ",", string: vers, replace: "." );
}
if(vers){
	if(version_is_less( version: vers, test_version: "10.3.183.23" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.2.202.236" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

