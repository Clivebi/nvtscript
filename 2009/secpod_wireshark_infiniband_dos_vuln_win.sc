if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900592" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-2563" );
	script_bugtraq_id( 35748 );
	script_name( "Wireshark Infiniband Dissector Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35884" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1970" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2009-04.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could result in denial of service condition." );
	script_tag( name: "affected", value: "Wireshark version 1.0.6 through 1.2.0 on Windows." );
	script_tag( name: "insight", value: "An unspecified error in the infiniband dissector which can be exploited when
  running on unspecified platforms via unknown vectors." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.2.1 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.0.6", test_version2: "1.2.0" )){
	report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "1.0.6 - 1.2.0" );
	security_message( port: 0, data: report );
}

