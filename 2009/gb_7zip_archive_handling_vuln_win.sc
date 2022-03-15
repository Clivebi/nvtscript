if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800261" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-6536" );
	script_bugtraq_id( 28285 );
	script_name( "7-Zip Unspecified Archive Handling Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/29434" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2008/0914/references" );
	script_xref( name: "URL", value: "http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_7zip_detect_portable_win.sc" );
	script_mandatory_keys( "7zip/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code in the
  affected system and cause denial of service." );
	script_tag( name: "affected", value: "7zip version prior to 4.57 on Windows." );
	script_tag( name: "insight", value: "This flaw occurs due to memory corruption while handling malformed archives." );
	script_tag( name: "solution", value: "Upgrade to 7zip version 4.57." );
	script_tag( name: "summary", value: "This host is installed with 7zip and is prone to Unspecified
  vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
version = get_kb_item( "7zip/Win/Ver" );
if(!version){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.57" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.57" );
	security_message( port: 0, data: report );
}

