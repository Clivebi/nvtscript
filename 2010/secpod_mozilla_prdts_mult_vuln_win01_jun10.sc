if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902205" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-07-01 15:58:11 +0200 (Thu, 01 Jul 2010)" );
	script_cve_id( "CVE-2010-1197", "CVE-2010-1198" );
	script_bugtraq_id( 41050 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Products Firefox/Seamonkey Multiple Vulnerabilities june-10 (Windows)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2010/mfsa2010-32.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2010/mfsa2010-28.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code." );
	script_tag( name: "affected", value: "Seamonkey version prior to 2.0.5,

  Firefox version 3.5.x before 3.5.10 and 3.6.x before 3.6.4" );
	script_tag( name: "insight", value: "The flaws are due to:

  - Use-after-free vulnerability exists in the application, which allows
  attackers to execute arbitrary code via multiple plugin instances.

  - Error in the handling of HTTP headers, which does not properly handle
  situations in which both 'Content-Disposition: attachment' and
  'Content-Type: multipart' are present in HTTP headers, which allows
  attackers to conduct cross-site scripting (XSS) attacks via an uploaded HTML document." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox/Seamonkey and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.5.10, 3.6.4

  Upgrade to Seamonkey version 2.0.5" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "3.5.0", test_version2: "3.5.9" ) || version_in_range( version: ffVer, test_version: "3.6.0", test_version2: "3.6.3" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(smVer != NULL){
	if(version_is_less( version: smVer, test_version: "2.0.5" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
