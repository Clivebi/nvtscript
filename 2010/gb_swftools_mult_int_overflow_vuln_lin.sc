if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801439" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)" );
	script_cve_id( "CVE-2010-1516" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "SWFTools Multiple Integer Overflow Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39970" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2010-80/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/513102/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_swftools_detect_lin.sc" );
	script_mandatory_keys( "SWFTools/Ver" );
	script_tag( name: "insight", value: "The flaws are due to an error within the 'getPNG()' function in
'lib/png.c' and 'jpeg_load()' function in 'lib/jpeg.c'." );
	script_tag( name: "solution", value: "Upgrade to version 0.9.2 or later." );
	script_tag( name: "summary", value: "This host is installed with SWFTools and is prone to multiple
integer overflow vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a
heap-based buffer overflow via specially crafted JPEG and PNG images." );
	script_tag( name: "affected", value: "SWFTools version 0.9.1 and prior." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.swftools.org/download.html" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("version_func.inc.sc");
swfVer = get_kb_item( "SWFTools/Ver" );
if(swfVer != NULL){
	if(version_is_less_equal( version: swfVer, test_version: "0.9.1" )){
		report = report_fixed_ver( installed_version: swfVer, vulnerable_range: "Less than or equal to 0.9.1" );
		security_message( port: 0, data: report );
	}
}

