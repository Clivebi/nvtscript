if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903023" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2011-1591" );
	script_bugtraq_id( 47392 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-04-25 18:34:41 +0530 (Wed, 25 Apr 2012)" );
	script_name( "Wireshark DECT Buffer Overflow Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44172" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/66834" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/1022" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2011-06.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause buffer overflow and
  execute arbitrary code on the system." );
	script_tag( name: "affected", value: "Wireshark version 1.4.0 through 1.4.4" );
	script_tag( name: "insight", value: "The flaw is due to error in the 'DECT' dissector when processing
  malformed data, which could allow code execution via malformed packets or
  a malicious PCAP file." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.4.5 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to buffer
  overflow vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_in_range( version: wiresharkVer, test_version: "1.4.0", test_version2: "1.4.4" )){
	report = report_fixed_ver( installed_version: wiresharkVer, vulnerable_range: "1.4.0 - 1.4.4" );
	security_message( port: 0, data: report );
}

