if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901033" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3242" );
	script_bugtraq_id( 36408 );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36754" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2009-06.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3893" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_lin.sc" );
	script_mandatory_keys( "Wireshark/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could result in Denial of service condition." );
	script_tag( name: "affected", value: "Wireshark version 1.2.0 to 1.2.1 on Windows" );
	script_tag( name: "insight", value: "An unspecified error in 'packet.c' in the GSM A RR dissector caused via
  unknown vectors related to 'an uninitialized dissector handle, ' which
  triggers an assertion failure." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.2.2." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  Denial of Service vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Linux/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.2.0", test_version2: "1.2.1" )){
	report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "1.2.0 - 1.2.1" );
	security_message( port: 0, data: report );
}

