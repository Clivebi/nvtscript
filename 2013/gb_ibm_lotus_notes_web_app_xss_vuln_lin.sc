if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803216" );
	script_version( "$Revision: 11865 $" );
	script_cve_id( "CVE-2012-4846" );
	script_bugtraq_id( 56944 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-01-23 13:22:09 +0530 (Wed, 23 Jan 2013)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "IBM Lotus Notes Web Application XSS Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51593" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027887" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/79535" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21619604" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_ibm_lotus_notes_detect_lin.sc" );
	script_mandatory_keys( "IBM/LotusNotes/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "IBM Lotus Notes Version 8.x before 8.5.3 FP3 on Linux" );
	script_tag( name: "insight", value: "An error exists within the Web applications which allows an attacker to read
  or set the cookie value by injecting script." );
	script_tag( name: "solution", value: "Upgrade to IBM Lotus Notes 8.5.3 FP3 or later." );
	script_tag( name: "summary", value: "This host is installed with IBM Lotus Notes and is prone to cross
  site scripting vulnerability." );
	exit( 0 );
}
require("version_func.inc.sc");
lotusVer = get_kb_item( "IBM/LotusNotes/Linux/Ver" );
if(!lotusVer){
	exit( 0 );
}
if(IsMatchRegexp( lotusVer, "^8\\.5" ) && version_is_less( version: lotusVer, test_version: "8.5.33" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

