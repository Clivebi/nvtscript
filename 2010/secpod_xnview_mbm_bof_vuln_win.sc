if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902075" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-22 13:34:32 +0200 (Tue, 22 Jun 2010)" );
	script_cve_id( "CVE-2010-1932" );
	script_bugtraq_id( 40852 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "XnView 'MBM' Processing Buffer Overflow Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_xnview_detect_win.sc" );
	script_mandatory_keys( "XnView/Win/Ver" );
	script_tag( name: "summary", value: "This host has XnView installed and is prone to a buffer overflow
  vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to improper bounds checking when processing 'MBM' (MultiBitMap)
  files, which could be exploited to cause a heap overflow." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to overflow a buffer and execute
  arbitrary code on the system with elevated privileges or cause the application
  to crash." );
	script_tag( name: "affected", value: "XnView versions prior to 1.97.5 on windows" );
	script_tag( name: "solution", value: "Update to XnView version 1.97.5" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/59421" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1468" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/Jun/1024100.html" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/content/XnView-MBM-Processing-Heap-Overflow" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!version = get_kb_item( "XnView/Win/Ver" )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.97.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.97.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

