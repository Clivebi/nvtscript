if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900068" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5715", "CVE-2009-2953" );
	script_bugtraq_id( 32988 );
	script_name( "Mozilla Firefox location.hash Remote DoS Vulnerability" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3424/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/32988/discuss" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/32988.pl" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/506006/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux_or_Win/installed" );
	script_tag( name: "impact", value: "Successful exploitation could result in remote arbitrary code execution,
  and can crash the affected browser." );
	script_tag( name: "affected", value: "Mozilla, Firefox version 3.0 through 3.0.13 and 3.5.x" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.3 or later" );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
  to denial of service vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to improper way of handling input passed to
  location.hash." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(!ffVer){
	ffVer = get_kb_item( "Firefox/Linux/Ver" );
	if(!ffVer){
		exit( 0 );
	}
}
if(version_in_range( version: ffVer, test_version: "3.0", test_version2: "3.0.13" ) || version_in_range( version: ffVer, test_version: "3.5", test_version2: "3.5.2" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

