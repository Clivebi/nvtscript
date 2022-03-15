if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801331" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)" );
	script_cve_id( "CVE-2010-1728" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Opera Browser 'document.write()' Code execution Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39590" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/58231" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/953/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0999" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/windows/1053/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to corrupt memory and execute
  arbitrary code by tricking a user into visiting a specially crafted web page." );
	script_tag( name: "affected", value: "Opera version prior to 10.53 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an error when continuously modifying document content
  on a web page using 'document.write()' function." );
	script_tag( name: "solution", value: "Upgrade to the opera version 10.53 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Opera web browser and is prone to
  arbitrary code execution vulnerability." );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "10.53" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "10.53" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

