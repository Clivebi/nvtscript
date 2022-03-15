if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800374" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-6472" );
	script_name( "Wireshark Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32840" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2008-07.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful attacks may cause the application to crash via unspecified
  attack vectors." );
	script_tag( name: "affected", value: "Wireshark version prior to 1.0.5 on Windows" );
	script_tag( name: "insight", value: "Error in the WLCCP and SMTP dissector allows to exploit by triggering the
  execution into an infinite loop through specially crafted packets." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.0.5." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to denial
  of service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_is_less( version: sharkVer, test_version: "1.0.5" )){
	report = report_fixed_ver( installed_version: sharkVer, fixed_version: "1.0.5" );
	security_message( port: 0, data: report );
}

