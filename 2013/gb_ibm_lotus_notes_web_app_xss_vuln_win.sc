if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803215" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_cve_id( "CVE-2012-4846" );
	script_bugtraq_id( 56944 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2013-01-23 13:22:09 +0530 (Wed, 23 Jan 2013)" );
	script_name( "IBM Lotus Notes Web Application XSS Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51593" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027887" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/79535" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21619604" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_ibm_lotus_notes_detect_win.sc" );
	script_mandatory_keys( "IBM/LotusNotes/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "IBM Lotus Notes Version 8.x before 8.5.3 FP3 on Windows." );
	script_tag( name: "insight", value: "An error exists within the Web applications which allows an attacker to read
  or set the cookie value by injecting script." );
	script_tag( name: "solution", value: "Upgrade to IBM Lotus Notes 8.5.3 FP3 or later." );
	script_tag( name: "summary", value: "This host is installed with IBM Lotus Notes and is prone to cross
  site scripting vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
lotusVer = get_kb_item( "IBM/LotusNotes/Win/Ver" );
if(!lotusVer){
	exit( 0 );
}
if(version_in_range( version: lotusVer, test_version: "8.5.0", test_version2: "8.5.32.12184" )){
	report = report_fixed_ver( installed_version: lotusVer, vulnerable_range: "8.5.0 - 8.5.32.12184" );
	security_message( port: 0, data: report );
}

