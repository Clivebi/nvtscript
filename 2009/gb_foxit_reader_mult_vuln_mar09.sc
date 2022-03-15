if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800537" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2009-03-17 05:28:51 +0100 (Tue, 17 Mar 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0836", "CVE-2009-0837", "CVE-2009-0191" );
	script_bugtraq_id( 34035 );
	script_name( "Foxit Reader Multiple Vulnerabilities Mar-09" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/369876.php" );
	script_xref( name: "URL", value: "http://www.security-database.com/detail.php?alert=CVE-2009-0837" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_foxit_reader_detect_portable_win.sc" );
	script_mandatory_keys( "foxit/reader/ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attacker execute arbitrary code via
  relative and absolute paths and to dereference uninstalled memory." );
	script_tag( name: "affected", value: "Foxit Reader 2.3 before Build 3902 and 3.0 before Build 1506." );
	script_tag( name: "insight", value: "- application does not require user confirmation before performing dangerous
  actions

  - stack based buffer overflow while processing a PDF file containing an
    action with overly long filename argument

  - error while processing JBIG2 symbol dictionary segment with zero new
    symbols" );
	script_tag( name: "solution", value: "Upgrade to the latest version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Foxit Reader and is prone to
  multiple vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
foxVer = get_kb_item( "foxit/reader/ver" );
if(!foxVer){
	exit( 0 );
}
if(version_is_less( version: foxVer, test_version: "2.3.2008.3902" ) || ( version_in_range( version: foxVer, test_version: "3.0", test_version2: "3.0.2009.1505" ) )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

