if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900559" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1829" );
	script_bugtraq_id( 35081 );
	script_name( "Wireshark PCNFSD Dissector Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1408" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the user crash the application to cause
  denial of service condition." );
	script_tag( name: "affected", value: "Wireshark version 0.8.20 through 1.0.7 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an error in the PCNFSD dissector when processing specially
  crafted large PCNFSD packets." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.0.8." );
	script_tag( name: "summary", value: "The remote host is installed with Wireshark and is prone to
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
if(version_in_range( version: sharkVer, test_version: "0.8.20", test_version2: "1.0.7" )){
	report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "0.8.20 - 1.0.7" );
	security_message( port: 0, data: report );
}

