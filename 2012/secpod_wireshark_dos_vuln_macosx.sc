if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903024" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2011-0538" );
	script_bugtraq_id( 46167 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-04-25 17:03:00 +0530 (Wed, 25 Apr 2012)" );
	script_name( "Wireshark Denial of Service Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65182" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/02/04/1" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5652" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a denial of
  service, execution of arbitrary code." );
	script_tag( name: "affected", value: "Wireshark version 1.5.0
  Wireshark version 1.2.0 through 1.2.14
  Wireshark version 1.4.0 through 1.4.3" );
	script_tag( name: "insight", value: "The flaw is due to uninitialized pointer during processing of a '.pcap'
  file in the pcap-ng format." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.2.15 or 1.4.4 or later." );
	script_tag( name: "summary", value: "This host is installed Wireshark and is prone to denial of service
  vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_in_range( version: wiresharkVer, test_version: "1.4.0", test_version2: "1.4.3" ) || version_in_range( version: wiresharkVer, test_version: "1.2.0", test_version2: "1.2.14" ) || version_is_equal( version: wiresharkVer, test_version: "1.5.0" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

