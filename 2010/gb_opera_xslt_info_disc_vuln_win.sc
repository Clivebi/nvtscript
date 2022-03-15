if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801310" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)" );
	script_cve_id( "CVE-2010-1310" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Opera 'XSLT' Information Disclosure Vulnerability - (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38820" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/949/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/windows/1051/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain sensitive
  information via a crafted document." );
	script_tag( name: "affected", value: "Opera version 10.50 and on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an error in handling of 'XSLT' constructs which can
  cause Opera to retrieve the wrong contents for the resulting document. These
  contents will appear randomly from the cached versions of any Web page that
  has previously been visited." );
	script_tag( name: "solution", value: "Upgrade to the opera version 10.51 or later." );
	script_tag( name: "summary", value: "The host is installed with Opera Web Browser and is prone to
  information disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "10.51" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "10.51" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

