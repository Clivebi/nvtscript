if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803068" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-6053", "CVE-2012-6062", "CVE-2012-6061", "CVE-2012-6060", "CVE-2012-6059", "CVE-2012-6058" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-12-07 18:39:59 +0530 (Fri, 07 Dec 2012)" );
	script_name( "Wireshark Multiple Dissector Multiple DoS Vulnerabilities - Dec12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51422" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-31.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-35.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-36.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-37.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-38.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-40.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to denial of service or
  to consume excessive CPU resources." );
	script_tag( name: "affected", value: "Wireshark 1.6.x before 1.6.12, 1.8.x before 1.8.4 on Windows" );
	script_tag( name: "insight", value: "The flaws are due to an errors in USB, RTCP, WTP, iSCSI, ISAKMP and ICMPv6
  dissectors, which can be exploited to cause a crash." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.6.12 or 1.8.4 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.6.0", test_version2: "1.6.11" ) || version_in_range( version: sharkVer, test_version: "1.8.0", test_version2: "1.8.3" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

