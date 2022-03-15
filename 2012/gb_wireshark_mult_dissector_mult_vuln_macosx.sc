if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802982" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-5237", "CVE-2012-5238", "CVE-2012-5240" );
	script_bugtraq_id( 55754 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-10-11 17:06:48 +0530 (Thu, 11 Oct 2012)" );
	script_name( "Wireshark LDP PPP and HSRP dissector Multiple Vulnerabilities (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50843/" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-27.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-26.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-29.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7668" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7581" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application, to crash the affected application,
  or to consume excessive CPU resources." );
	script_tag( name: "affected", value: "Wireshark versions 1.8.x prior to 1.8.3 on Mac OS X" );
	script_tag( name: "insight", value: "Errors in the HSRP, PPP and LDP dissectors when processing certain
  packets can be exploited to cause an infinite loop and consume CPU
  resources or a buffer overflow." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.8.3 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.8.0", test_version2: "1.8.2" )){
	report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "1.8.0 - 1.8.2" );
	security_message( port: 0, data: report );
}

