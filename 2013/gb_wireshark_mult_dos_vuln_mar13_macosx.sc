if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803332" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_cve_id( "CVE-2013-2478", "CVE-2013-2480", "CVE-2013-2481", "CVE-2013-2482", "CVE-2013-2483", "CVE-2013-2484", "CVE-2013-2485", "CVE-2013-2488" );
	script_bugtraq_id( 58357, 58351, 58340, 58353, 58355, 58356, 58362, 58365 );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2013-03-11 19:20:06 +0530 (Mon, 11 Mar 2013)" );
	script_name( "Wireshark Multiple Dissector Multiple DoS Vulnerabilities - March 13 (Mac OS X)" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/52471" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1028254" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause denial of
  service or to consume excessive CPU resources." );
	script_tag( name: "affected", value: "Wireshark 1.6.x before 1.6.14, 1.8.x before 1.8.6 on Mac OS X." );
	script_tag( name: "insight", value: "Multiple flaws are due to errors in MS-MMS, RTPS, RTPS2, Mount, AMPQ, ACN,
  CIMD, FCSP and DTLS dissectors." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.6.14 or 1.8.6 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(sharkVer && IsMatchRegexp( sharkVer, "^(1.6|1.8)" )){
	if(version_in_range( version: sharkVer, test_version: "1.6.0", test_version2: "1.6.11" ) || version_in_range( version: sharkVer, test_version: "1.8.0", test_version2: "1.8.3" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

