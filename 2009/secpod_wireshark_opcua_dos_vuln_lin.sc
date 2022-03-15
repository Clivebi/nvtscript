CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901032" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-3241" );
	script_bugtraq_id( 36408 );
	script_name( "Wireshark OpcUa Dissector Denial of Service Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_lin.sc" );
	script_mandatory_keys( "Wireshark/Linux/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36754" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2009-06.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2009-05.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3986" );
	script_tag( name: "impact", value: "Successful exploitation could result in Denial of service condition." );
	script_tag( name: "affected", value: "Wireshark version 0.99.6 to 1.0.8, 1.2.0 to 1.2.1 on Linux." );
	script_tag( name: "insight", value: "The flaw is due to unspecified error in 'OpcUa' dissector which can be
  exploited by sending malformed OPCUA Service CallRequest packets." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.0.9 or 1.2.2." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to Denial of
  Service vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: ver, test_version: "0.99.6", test_version2: "1.0.8" ) || version_in_range( version: ver, test_version: "1.2.0", test_version2: "1.2.1" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "1.0.9 or 1.2.2" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

