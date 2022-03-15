if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800074" );
	script_version( "2020-04-27T11:01:03+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 11:01:03 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2008-12-04 14:15:00 +0100 (Thu, 04 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5285" );
	script_bugtraq_id( 32422 );
	script_name( "Wireshark SMTP Processing Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2008/3231" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful attacks may cause the application to crash via specially
  crafted packets." );
	script_tag( name: "affected", value: "Wireshark version 1.0.4 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an error in the SMTP dissector while processing
  large SMTP packets." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.0.5." );
	script_tag( name: "summary", value: "The Remote host is installed with Wireshark and is prone to
  denial of service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_is_less_equal( version: sharkVer, test_version: "1.0.4" )){
	report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "Less than or equal to 1.0.4" );
	security_message( port: 0, data: report );
}

