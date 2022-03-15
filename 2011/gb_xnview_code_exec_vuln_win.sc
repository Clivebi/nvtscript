if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802309" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)" );
	script_cve_id( "CVE-2011-1338" );
	script_bugtraq_id( 48562 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "XnView File Search Path Executable File Injection Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_xnview_detect_win.sc" );
	script_mandatory_keys( "XnView/Win/Ver" );
	script_tag( name: "summary", value: "This host has XnView installed and is prone to an executable file
  injection vulnerability." );
	script_tag( name: "insight", value: "The flaw is caused by an untrusted search path vulnerability when loading
  executables." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code on the
  system with elevated privileges." );
	script_tag( name: "affected", value: "XnView versions prior to 1.98.1 on windows." );
	script_tag( name: "solution", value: "Update to XnView version 1.98.1 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68369" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!version = get_kb_item( "XnView/Win/Ver" )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.98.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.98.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

