if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800885" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3010", "CVE-2009-3014" );
	script_name( "Mozilla Product(s) 'javascript:' URI XSS Vulnerability - Sep09 (Windows)" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3315/" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3323/" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3373/" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3386/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/506163/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_mozilla_detect_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct
Cross-Site Scripting attacks in the victim's system." );
	script_tag( name: "affected", value: "Mozilla, Firefox version 3.0.13 and prior, 3.5, 3.6/3.7 a1 pre
Moziila Browser 1.7.13 and prior, Seamonkey 1.1.17 on Windows." );
	script_tag( name: "insight", value: "Application fails to sanitise the 'javascript:' and 'data:'
URIs in Refresh headers or Location headers in HTTP responses, which can be
exploited via vectors related to injecting a Refresh header or Location HTTP
response header." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Product(s) and is prone to
Cross-Site Scripting vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if( ffVer ){
	if(version_is_less_equal( version: ffVer, test_version: "3.0.13" ) || version_is_equal( version: ffVer, test_version: "3.5" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
else {
	if(registry_key_exists( key: "SOFTWARE\\Mozilla\\Minefield" )){
		for item in registry_enum_keys( key: "SOFTWARE\\Mozilla\\Minefield" ) {
			ver = eregmatch( pattern: "([0-9.]+a1pre)", string: item );
			if(IsMatchRegexp( ver, "^3\\.[6|7]a1pre" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(smVer != NULL){
	if(version_is_equal( version: smVer, test_version: "1.1.17" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
mbVer = get_kb_item( "Mozilla/Win/Ver" );
if(mbVer){
	if(version_is_less_equal( version: mbVer, test_version: "1.7.13" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

