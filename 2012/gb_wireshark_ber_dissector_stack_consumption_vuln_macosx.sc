if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802845" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2010-3445" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-05-04 18:26:03 +0530 (Fri, 04 May 2012)" );
	script_name( "Wireshark BER Dissector Stack Consumption Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/10/12/1" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/10/01/10" );
	script_xref( name: "URL", value: "http://xorl.wordpress.com/2010/10/15/cve-2010-3445-wireshark-asn-1-ber-stack-overflow/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to crash the application." );
	script_tag( name: "affected", value: "Wireshark version 1.4.x before 1.4.1 and 1.2.x before 1.2.12" );
	script_tag( name: "insight", value: "The flaw is due to stack consumption error in the
  'dissect_ber_unknown()' function in 'epan/dissectors/packet-ber.c' in the
  BER dissector, which allows remote attackers to cause a denial of service
  (NULL pointer dereference and crash) via a long string in an unknown
  'ASN.1/BER' encoded packet." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.4.1 or 1.2.12 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to stack
  consumption vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!sharkVer){
	exit( 0 );
}
if(version_is_equal( version: sharkVer, test_version: "1.4.0" ) || version_in_range( version: sharkVer, test_version: "1.2.0", test_version2: "1.2.11" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

