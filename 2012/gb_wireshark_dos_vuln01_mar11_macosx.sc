if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802799" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-1142" );
	script_bugtraq_id( 46626 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-06-27 15:59:15 +0530 (Wed, 27 Jun 2012)" );
	script_name( "Wireshark Denial of Service Vulnerability-01 March 11 (Mac OS X)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65912" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1516" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a
denial of service via vectors involving self-referential ASN.1 CHOICE values." );
	script_tag( name: "affected", value: "Wireshark version 1.2.0 through 1.2.15
Wireshark version 1.4.0 through 1.4.4" );
	script_tag( name: "insight", value: "The flaw is due to stack consumption vulnerability in the
'dissect_ber_choice function' in the 'BER dissector'." );
	script_tag( name: "solution", value: "Upgrade to version 1.4.4-1 or later." );
	script_tag( name: "summary", value: "The host is installed with Wireshark and is prone to denial of
service vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_in_range( version: wiresharkVer, test_version: "1.2.0", test_version2: "1.2.15" ) || version_in_range( version: wiresharkVer, test_version: "1.4.0", test_version2: "1.4.4" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

