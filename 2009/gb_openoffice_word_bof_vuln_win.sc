if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800696" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0200", "CVE-2009-0201" );
	script_bugtraq_id( 36200 );
	script_name( "OpenOffice.org Word Documents Parsing Buffer Overflow Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2009-27/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2490" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_openoffice_detect_win.sc" );
	script_mandatory_keys( "OpenOffice/Win/Ver" );
	script_tag( name: "impact", value: "Successful remote exploitation could result in arbitrary code execution on
  the affected system which leads to application crash and compromise a
  vulnerable system." );
	script_tag( name: "affected", value: "OpenOffice Version prior to 3.1.1 on Windows." );
	script_tag( name: "insight", value: "- An integer underflow error occurs when parsing certain records in a
    Word document table.

  - An heap overflow error occurs when parsing certain records in a Word
    document when opening a malicious Word document." );
	script_tag( name: "solution", value: "Upgrade to OpenOffice Version 3.1.1 or later" );
	script_tag( name: "summary", value: "The host has OpenOffice installed and is prone to Buffer
  Overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
openVer = get_kb_item( "OpenOffice/Win/Ver" );
if(!openVer){
	exit( 0 );
}
if(version_is_less( version: openVer, test_version: "3.1.9420" )){
	report = report_fixed_ver( installed_version: openVer, fixed_version: "3.1.9420" );
	security_message( port: 0, data: report );
}

