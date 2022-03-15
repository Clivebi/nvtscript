if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801030" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3615" );
	script_bugtraq_id( 36719 );
	script_name( "Pidgin Oscar Protocol Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37072" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53807" );
	script_xref( name: "URL", value: "http://www.pidgin.im/news/security/?id=41" );
	script_xref( name: "URL", value: "http://developer.pidgin.im/wiki/ChangeLog" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_pidgin_detect_win.sc" );
	script_mandatory_keys( "Pidgin/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a Denial of Service." );
	script_tag( name: "affected", value: "Pidgin version prior to 2.6.3 on Windows." );
	script_tag( name: "insight", value: "This issue is caused by an error in the Oscar protocol plugin when processing
  malformed ICQ or AIM contacts sent by the SIM IM client, which could cause an
  invalid memory access leading to a crash." );
	script_tag( name: "solution", value: "Upgrade to Pidgin version 2.6.3." );
	script_tag( name: "summary", value: "This host has Pidgin installed and is prone to Denial of Service
  vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
pidginVer = get_kb_item( "Pidgin/Win/Ver" );
if(!pidginVer){
	exit( 0 );
}
if(version_is_less( version: pidginVer, test_version: "2.6.3" )){
	report = report_fixed_ver( installed_version: pidginVer, fixed_version: "2.6.3" );
	security_message( port: 0, data: report );
}

