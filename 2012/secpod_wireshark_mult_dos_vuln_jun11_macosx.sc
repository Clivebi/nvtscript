if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902684" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2011-1957", "CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2174", "CVE-2011-2175" );
	script_bugtraq_id( 48066 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-06-29 16:35:04 +0530 (Fri, 29 Jun 2012)" );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities June-11 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44449/" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2011-07.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2011-08.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a denial of
  service condition." );
	script_tag( name: "affected", value: "Wireshark versions 1.2.x before 1.2.17 and 1.4.x before 1.4.7 on Mac OS X" );
	script_tag( name: "insight", value: "- An error in the DICOM dissector can be exploited to cause an infinite loop
    when processing certain malformed packets.

  - An error when processing a Diameter dictionary file can be exploited to
    cause the process to crash.

  - An error when processing a snoop file can be exploited to cause the process
    to crash.

  - An error when processing compressed capture data can be exploited to cause
    the process to crash.

  - An error when processing a Visual Networks file can be exploited to cause
    the process to crash." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.2.17 or 1.4.7 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.2.0", test_version2: "1.2.16" ) || version_in_range( version: sharkVer, test_version: "1.4.0", test_version2: "1.4.6" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

