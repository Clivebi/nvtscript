if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801554" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)" );
	script_cve_id( "CVE-2010-4301" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Wireshark ZigBee ZCL Dissector Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42290" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/3038" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2010-14.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to crash the application." );
	script_tag( name: "affected", value: "Wireshark version 1.4.0 to 1.4.1" );
	script_tag( name: "insight", value: "The flaw is due to error in 'epan/dissectors/packet-zbee-zcl.c' in the
  ZigBee ZCL dissector, which allows remote attackers to cause a denial of
  service (infinite loop) via a crafted ZCL packet." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.4.2 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to denial of
  service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.4.0", test_version2: "1.4.1" )){
	report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "1.4.0 - 1.4.1" );
	security_message( port: 0, data: report );
}

