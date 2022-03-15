if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800066" );
	script_version( "2020-04-27T11:01:03+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 11:01:03 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5178" );
	script_bugtraq_id( 32323 );
	script_name( "Opera Web Browser Heap Based Buffer Overflow Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/7135" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/3183" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful remote attack could allow arbitrary code execution
  by tricking user into opening malicious HTML file." );
	script_tag( name: "affected", value: "Opera version 9.62 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an error while processing an overly long
  file:// URI." );
	script_tag( name: "solution", value: "Upgrade to Opera 9.63." );
	script_tag( name: "summary", value: "The host is installed with Opera Web Browser and is prone to
  buffer overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less_equal( version: operaVer, test_version: "9.62" )){
	report = report_fixed_ver( installed_version: operaVer, vulnerable_range: "Less than or equal to 9.62" );
	security_message( port: 0, data: report );
}

