if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802804" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2012-0752", "CVE-2012-0753", "CVE-2012-0754", "CVE-2012-0757", "CVE-2012-0756", "CVE-2012-0767" );
	script_bugtraq_id( 52032, 52033, 52034, 51999, 52036, 52040 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-22 14:34:05 +0530 (Wed, 22 Feb 2012)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities (Linux) - Feb12" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48033" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026694" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/48033" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-03.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the affected application or cause a denial of service condition." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 10.3.183.15
  Adobe Flash Player version 11.x through 11.1.102.55 on Linux." );
	script_tag( name: "insight", value: "The flaws are due to:

  - A memory corruption error in ActiveX control

  - A type confusion memory corruption error

  - An unspecified error related to MP4 parsing

  - Many unspecified errors which allows to bypass certain security
  restrictions

  - Improper validation of user supplied input which allows attackers to
  execute arbitrary HTML and script code in a user's browser session." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.3.183.15 or 11.1.102.62 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
flashVer = get_kb_item( "AdobeFlashPlayer/Linux/Ver" );
if(isnull( flashVer )){
	exit( 0 );
}
flashVer = ereg_replace( pattern: ",", string: flashVer, replace: "." );
if(version_is_less( version: flashVer, test_version: "10.3.183.15" ) || version_in_range( version: flashVer, test_version: "11.0", test_version2: "11.1.102.55" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

