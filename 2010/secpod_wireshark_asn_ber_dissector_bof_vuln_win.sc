if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902195" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-22 13:34:32 +0200 (Tue, 22 Jun 2010)" );
	script_cve_id( "CVE-2010-2284" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Wireshark ASN.1 BER Dissector Buffer Overflow Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40112" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1418" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2010-05.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2010-06.html" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/06/11/1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "It has unknown impact and remote attack vectors." );
	script_tag( name: "affected", value: "Wireshark version 0.10.13 to 1.0.13 and 1.2.0 to 1.2.8 on windows." );
	script_tag( name: "insight", value: "The flaw is caused by a buffer overflow error within the 'ASN.1 BER' dissector." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.0.14 or 1.2.9:" );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to buffer overflow
  vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.2.0", test_version2: "1.2.8" ) || version_in_range( version: sharkVer, test_version: "0.10.13", test_version2: "1.0.13" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

