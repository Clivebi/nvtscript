if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803650" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-4083" );
	script_bugtraq_id( 60504 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-05-28 13:30:52 +0530 (Tue, 28 May 2013)" );
	script_name( "Wireshark DCP ETSI Dissector DoS Vulnerability - June 13 (Windows)" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028648" );
	script_xref( name: "URL", value: "http://www.security-database.com/detail.php?alert=CVE-2013-4083" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2013-41.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause denial of
  service by injecting a malformed packet." );
	script_tag( name: "affected", value: "Wireshark 1.6.x before 1.6.16, 1.8.x before 1.8.8 and 1.10.0 on Windows" );
	script_tag( name: "insight", value: "- 'dissect_pft function' function in epan/dissectors/packet-dcp-etsi.c does
     not validate fragment length value." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.6.16 or 1.8.8 or 1.10.1 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to denial of
  service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(sharkVer && IsMatchRegexp( sharkVer, "^(1.6|1.8|1.10)" )){
	if(sharkVer == "1.10.0" || version_in_range( version: sharkVer, test_version: "1.6.0", test_version2: "1.6.15" ) || version_in_range( version: sharkVer, test_version: "1.8.0", test_version2: "1.8.7" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

