if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803331" );
	script_version( "2019-05-16T08:02:32+0000" );
	script_cve_id( "CVE-2013-2486", "CVE-2013-2487", "CVE-2013-2479", "CVE-2013-2477", "CVE-2013-2476", "CVE-2013-2475" );
	script_bugtraq_id( 58363, 58350, 58354, 58358, 58349, 58364 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2019-05-16 08:02:32 +0000 (Thu, 16 May 2019)" );
	script_tag( name: "creation_date", value: "2013-03-11 18:15:06 +0530 (Mon, 11 Mar 2013)" );
	script_name( "Wireshark Multiple Dissector Multiple Vulnerabilities - March 13 (Windows)" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/52471" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1028254" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a Denial of
  Service or to consume excessive CPU resources." );
	script_tag( name: "affected", value: "Wireshark versions 1.8.x before 1.8.6 on Windows." );
	script_tag( name: "insight", value: "Multiple flaws are due to errors in RELOAD, MPLS Echo, CSN.1, HART/IP and TCP
  dissectors." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.8.6 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(sharkVer && IsMatchRegexp( sharkVer, "^1\\.8" )){
	if(version_in_range( version: sharkVer, test_version: "1.8.0", test_version2: "1.8.5" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

