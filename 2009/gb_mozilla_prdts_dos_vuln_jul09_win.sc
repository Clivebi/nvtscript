if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800848" );
	script_version( "$Revision: 12629 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-2535", "CVE-2009-1692" );
	script_bugtraq_id( 35446 );
	script_name( "Mozilla Products 'select()' Denial Of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9160" );
	script_xref( name: "URL", value: "http://www.g-sec.lu/one-bug-to-rule-them-all.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause application crash by
  consuming the memory." );
	script_tag( name: "affected", value: "Seamonkey version prior to 1.1.17
  Thunderbird version 2.0.0.22 and prior
  Firefox version before 2.0.0.19 and 3.x before 3.0.5 on Windows." );
	script_tag( name: "insight", value: "A null pointer dereference error occurs while calling the 'select' method with
  a large integer, that results in continuous allocation of x+n bytes of memory exhausting memory after a while." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone
  to Denial of Service vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 2.0.0.19 or 3.0.5 or later

  Upgrade to Seamonkey version 1.1.17 or later

  Apply patch for Thunderbird through above mozilla engine update." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_is_less( version: ffVer, test_version: "2.0.0.19" ) || version_in_range( version: ffVer, test_version: "3.0", test_version2: "3.0.4" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(smVer != NULL){
	if(version_is_less( version: smVer, test_version: "1.1.17" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
tbVer = get_kb_item( "Thunderbird/Win/Ver" );
if(tbVer != NULL){
	if(version_is_less_equal( version: tbVer, test_version: "2.0.0.22" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

