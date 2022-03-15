if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800593" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2261" );
	script_name( "PeaZIP Remote Code Execution Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.vulnaware.com/?p=16018" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35352/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_peazip_detect_win.sc" );
	script_mandatory_keys( "PeaZIP/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to exectue arbitrary code on
  the affected system via files containing shell metacharacters and commands
  contained in a ZIP archive." );
	script_tag( name: "affected", value: "PeaZIP version 2.6.1 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw is due to insufficient sanitation of input data while
  processing the names of archived files." );
	script_tag( name: "solution", value: "Update to PeaZIP version 2.6.2." );
	script_tag( name: "summary", value: "This host is installed with PeaZIP and is prone to Remote
  Code Execution vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
version = get_kb_item( "PeaZIP/Win/Ver" );
if(!version){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.6.1" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Less than or equal to 2.6.1" );
	security_message( port: 0, data: report );
}

