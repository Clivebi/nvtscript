if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801785" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)" );
	script_cve_id( "CVE-2011-1590" );
	script_bugtraq_id( 47392 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Wireshark X.509if Dissector Denial of service vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025388" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/1022" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a denial of service via
  a crafted .pcap file." );
	script_tag( name: "affected", value: "Wireshark version 1.2.0 through 1.2.15
  Wireshark version 1.4.0 through 1.4.4" );
	script_tag( name: "insight", value: "The flaw is caused by an error in the 'X.509if' dissector when processing
  malformed data, which could be exploited to crash an affected application." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.4.5 or 1.2.16 or later." );
	script_tag( name: "summary", value: "The host is installed with Wireshark and is prone to denial of
  service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_in_range( version: wiresharkVer, test_version: "1.2.0", test_version2: "1.2.15" ) || version_in_range( version: wiresharkVer, test_version: "1.4.0", test_version2: "1.4.4" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

