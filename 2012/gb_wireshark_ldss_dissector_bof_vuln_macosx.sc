if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802847" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2010-4300" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-05-04 18:49:10 +0530 (Fri, 04 May 2012)" );
	script_name( "Wireshark LDSS Dissector Buffer Overflow Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42290" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/3038" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2010-14.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to crash the application." );
	script_tag( name: "affected", value: "Wireshark version 1.2.0 to 1.2.12 and 1.4.0 to 1.4.1" );
	script_tag( name: "insight", value: "The flaw is due to heap based buffer overflow in
  'dissect_ldss_transfer()' function (epan/dissectors/packet-ldss.c) in the
  LDSS dissector, which allows attackers to cause a denial of service (crash)
  and possibly execute arbitrary code via an LDSS packet with a long digest
  line." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.4.2 or 1.2.13 later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to buffer
  overflow vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.4.0", test_version2: "1.4.1" ) || version_in_range( version: sharkVer, test_version: "1.2.0", test_version2: "1.2.12" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

