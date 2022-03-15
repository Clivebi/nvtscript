if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902722" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)" );
	script_cve_id( "CVE-2011-3266" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_name( "Wireshark IKE Packet Denial of Service Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_family( "Denial of Service" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to send a specially crafted IKE
  packet to cause the IKEv1 dissector to enter an infinite loop, which leads
  to denial of service." );
	script_tag( name: "affected", value: "Wireshark version 1.6.0 to 1.6.1
  Wireshark version 1.4.0 to 1.4.8 on Windows" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'IKEv1' protocol dissector and the
  function 'proto_tree_add_item()', when add more than 1000000 items to a
  proto_tree, that will cause a denial of service." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.4.9, 1.6.2 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to denial of
  service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025875" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/519049/100/0/threaded" );
	exit( 0 );
}
require("version_func.inc.sc");
wireVer = get_kb_item( "Wireshark/Win/Ver" );
if(!wireVer){
	exit( 0 );
}
if(version_in_range( version: wireVer, test_version: "1.6.0", test_version2: "1.6.1" ) || version_in_range( version: wireVer, test_version: "1.4.0", test_version2: "1.4.8" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

