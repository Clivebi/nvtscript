if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800327" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5756" );
	script_bugtraq_id( 33023 );
	script_name( "BreakPoint Software Hex Workshop Denial of Service vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/Advisories/33327" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7592" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_bpsoft_hex_workshop_detect.sc" );
	script_mandatory_keys( "BPSoft/HexWorkshop/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code and
  can cause Denial of Service to the application." );
	script_tag( name: "affected", value: "BreakPoint Software Hex Workshop version 5.1.4 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw is due to improper boundary checks in Color Mapping or
  .cmap file via a long mapping reference." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to BreakPoint Software Hex Workshop version 6.0.1 or later." );
	script_tag( name: "summary", value: "This host has Hex Workshop installed and is prone to Denial of
  Service vulnerability." );
	exit( 0 );
}
require("version_func.inc.sc");
hwVer = get_kb_item( "BPSoft/HexWorkshop/Ver" );
if(!hwVer){
	exit( 0 );
}
if(version_in_range( version: hwVer, test_version: "1.0", test_version2: "5.1.4.4188" )){
	report = report_fixed_ver( installed_version: hwVer, vulnerable_range: "1.0 - 5.1.4.4188" );
	security_message( port: 0, data: report );
}

