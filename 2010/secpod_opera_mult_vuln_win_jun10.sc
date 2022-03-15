if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902203" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)" );
	script_cve_id( "CVE-2010-2421" );
	script_bugtraq_id( 40973 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Opera Browser Multiple Vulnerabilities (Windows)" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to bypass certain
  restrictions, disclose sensitive information or execute arbitrary code." );
	script_tag( name: "affected", value: "Opera version prior to 10.54 and on Windows." );
	script_tag( name: "insight", value: "The flaws are due to an unspecified errors when processing the vectors
  related to 'extremely severe', 'highly severe', 'moderately severe', and
  'less severe' issues." );
	script_tag( name: "solution", value: "Upgrade to the opera version 10.54 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Opera Web Browser and is prone to
  multiple vulnerabilities." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40250" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/955/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/mac/1054/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1529" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "10.54" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "10.54" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

