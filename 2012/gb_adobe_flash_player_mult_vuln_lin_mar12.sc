if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802810" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0769", "CVE-2012-0768" );
	script_bugtraq_id( 52299, 52297 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-03-12 18:30:17 +0530 (Mon, 12 Mar 2012)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities (Linux) - Mar12" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48281/" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-05.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the affected
  application or cause a denial of service condition." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 10.3.183.16 on Linux
  Adobe Flash Player version 11.x before 11.1.102.63 on Linux" );
	script_tag( name: "insight", value: "The flaws are due to an integer errors and Unspecified error in Matrix3D
  component." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.3.183.16 or 11.1.102.63 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "AdobeFlashPlayer/Linux/Ver" );
if(!vers){
	exit( 0 );
}
vers = ereg_replace( pattern: ",", string: vers, replace: "." );
if(version_is_less( version: vers, test_version: "10.3.183.16" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.1.102.62" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

