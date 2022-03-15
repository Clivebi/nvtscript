if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902003" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3981", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986", "CVE-2009-3987" );
	script_bugtraq_id( 37369, 37368, 37361, 37362, 37363, 37364, 37366, 37367, 37370, 37365, 37360 );
	script_name( "Seamonkey Multiple Vulnerabilities Dec-09 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37699" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3547" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-65.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-66.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-67.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-68.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-69.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-70.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-71.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_seamonkey_detect_win.sc" );
	script_mandatory_keys( "Seamonkey/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to conduct spoofing attacks,
  bypass certain security restrictions, manipulate certain data, disclose
  sensitive information, or compromise a user's system." );
	script_tag( name: "affected", value: "Seamonkey version prior to 2.0.1 on Windows." );
	script_tag( name: "insight", value: "Please see the references for more information about the vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Seamonkey version 2.0.1." );
	script_tag( name: "summary", value: "The host is installed with Seamonkey and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(smVer){
	if(version_is_less( version: smVer, test_version: "2.0.1" )){
		report = report_fixed_ver( installed_version: smVer, fixed_version: "2.0.1" );
		security_message( port: 0, data: report );
	}
}

