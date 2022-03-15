if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802761" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0068", "CVE-2012-0067", "CVE-2012-0066", "CVE-2012-0043", "CVE-2012-0042", "CVE-2012-0041" );
	script_bugtraq_id( 51710, 51368 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-04-23 18:33:55 +0530 (Mon, 23 Apr 2012)" );
	script_name( "Wireshark Multiple Vulnerabilities - April 12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47494/" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-01.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  or cause a denial of service." );
	script_tag( name: "affected", value: "Wireshark versions 1.4.x before 1.4.11 and 1.6.x before 1.6.5 on Windows" );
	script_tag( name: "insight", value: "The flaws are due to

  - NULL pointer dereference errors when reading certain packet information
    can be exploited to cause a crash.

  - An error within the RLC dissector can be exploited to cause a buffer
    overflow via a specially crafted RLC packet capture file.

  - An error within the 'lanalyzer_read()' function (wiretap/lanalyzer.c) when
    parsing LANalyzer files can be exploited to cause a heap-based buffer
    underflow." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.4.11, 1.6.5 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.4.0", test_version2: "1.4.10" ) || version_in_range( version: sharkVer, test_version: "1.6.0", test_version2: "1.6.4" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

