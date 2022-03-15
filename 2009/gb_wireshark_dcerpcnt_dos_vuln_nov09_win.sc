if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801034" );
	script_version( "2019-04-29T15:08:03+0000" );
	script_tag( name: "last_modification", value: "2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)" );
	script_tag( name: "creation_date", value: "2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3550" );
	script_bugtraq_id( 36846 );
	script_name( "Wireshark 'DCERPC/NT' Dissector DOS Vulnerability - Nov09 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37175" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54016" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3689" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.2.3.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.0.10.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2009-07.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2009-08.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could result in Denial of service condition." );
	script_tag( name: "affected", value: "Wireshark version 0.10.13 to 1.0.9 and 1.2.0 to 1.2.2 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to a NULL pointer dereference error within the 'DCERPC/NT'
  dissector that can be exploited to cause a crash." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to Denial of
  Service Vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.0.10 or 1.2.3." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.2.0", test_version2: "1.2.2" ) || version_in_range( version: sharkVer, test_version: "0.10.13", test_version2: "1.0.9" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

