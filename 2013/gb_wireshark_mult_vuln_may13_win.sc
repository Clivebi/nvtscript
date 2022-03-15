if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803620" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-3562", "CVE-2013-3561", "CVE-2013-3560", "CVE-2013-3559", "CVE-2013-3558", "CVE-2013-3555" );
	script_bugtraq_id( 59998, 60002, 59996, 60001, 59999, 60000, 59995, 60003, 59994, 59992 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-05-28 15:30:37 +0530 (Tue, 28 May 2013)" );
	script_name( "Wireshark Multiple Dissector Multiple Vulnerabilities - May 13 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53425" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.8.7.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to crash the
  application, resulting in denial of service condition." );
	script_tag( name: "affected", value: "Wireshark versions 1.8.x before 1.8.7 on Windows" );
	script_tag( name: "insight", value: "Multiple flaws are due to errors in Websocket, MySQL, ETCH, MPEG DSM-CC,
  DCP ETSI, PPP CCP and GTPv2 dissectors." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.8.7 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(sharkVer && IsMatchRegexp( sharkVer, "^1\\.8" )){
	if(version_in_range( version: sharkVer, test_version: "1.8.0", test_version2: "1.8.6" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

