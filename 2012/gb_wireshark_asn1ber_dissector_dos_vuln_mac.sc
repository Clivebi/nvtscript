if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802665" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_bugtraq_id( 45775 );
	script_cve_id( "CVE-2011-0445" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-07-30 17:17:17 +0530 (Mon, 30 Jul 2012)" );
	script_name( "Wireshark ASN.1 BER Dissector Denial of Service Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/64625" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0079" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2011-02.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5537" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to create a denial of service." );
	script_tag( name: "affected", value: "Wireshark versions 1.4.0 through 1.4.2 on Mac OS X" );
	script_tag( name: "insight", value: "The flaw is caused by an assertion error in the ASN.1 BER dissector, which
  could be exploited to crash an affected application." );
	script_tag( name: "solution", value: "Upgrade to the latest version of Wireshark 1.4.3 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to denial of
  service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.4.0", test_version2: "1.4.2" )){
	report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "1.4.0 - 1.4.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

