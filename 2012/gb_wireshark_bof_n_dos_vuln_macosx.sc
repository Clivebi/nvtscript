if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802767" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-4102", "CVE-2011-4101" );
	script_bugtraq_id( 50486, 50481 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-05-02 17:03:46 +0530 (Wed, 02 May 2012)" );
	script_name( "Wireshark Heap Based BOF and Denial of Service Vulnerabilities (Mac OS X)" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a denial of service via
  via a malformed packet." );
	script_tag( name: "affected", value: "Wireshark version 1.4.0 through 1.4.9 and 1.6.x before 1.6.3 on Mac OS X" );
	script_tag( name: "insight", value: "The flaws are due to

  - An error while parsing ERF file format. This could cause wireshark to
    crash by reading a malformed packet trace file.

  - An error in dissect_infiniband_common function in
    'epan/dissectors/packet-infiniband.c' in the Infiniband dissector,
    could dereference a NULL pointer." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.6.3 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to heap based
  buffer overflow and denial of service vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=750645" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/11/01/9" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6476" );
	script_xref( name: "URL", value: "http://anonsvn.wireshark.org/viewvc?view=revision&revision=39508" );
	script_xref( name: "URL", value: "http://anonsvn.wireshark.org/viewvc?view=revision&revision=39500" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_in_range( version: wiresharkVer, test_version: "1.4.0", test_version2: "1.4.9" ) || version_in_range( version: wiresharkVer, test_version: "1.6.0", test_version2: "1.6.2" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

