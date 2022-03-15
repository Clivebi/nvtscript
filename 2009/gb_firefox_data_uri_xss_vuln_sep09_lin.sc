if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800890" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3012" );
	script_name( "Mozilla Firefox 'data:' URI XSS Vulnerability - Sep09 (Linux)" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3323/" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3386/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct Cross-Site Scripting
  attacks in the victim's system." );
	script_tag( name: "affected", value: "Mozilla, Firefox version 3.0.13 and prior, 3.5 and 3.6/3.7 a1 pre on Linux." );
	script_tag( name: "insight", value: "Firefox fails to sanitise the 'data:' URIs in Location headers in HTTP
  responses, which can be exploited via vectors related to injecting a Location
  header or Location HTTP response header." );
	script_tag( name: "solution", value: "Upgrade Firefox version 3.6.3 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Product(s) and is prone to
  Cross-Site Scripting vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
ffVer = get_kb_item( "Firefox/Linux/Ver" );
if(!ffVer){
	exit( 0 );
}
if( version_is_less_equal( version: ffVer, test_version: "3.0.13" ) || version_is_equal( version: ffVer, test_version: "3.5" ) ){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(IsMatchRegexp( ffVer, "^3\\.[6|7]a1pre" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
