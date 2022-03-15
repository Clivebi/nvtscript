if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800390" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1232" );
	script_name( "Firefox XUL Parsing Denial of Service Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8306" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/49521" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause the browser to crash." );
	script_tag( name: "affected", value: "Firefox version 3.0 to 3.0.8 on Linux." );
	script_tag( name: "insight", value: "Error in browser due to improper parsing of XUL (XML) documents while opening
  a specially-crafted XML document containing long series of start-tags with no
  corresponding end-tags." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.6.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone to
  XUL Parsing Vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Linux/Ver" );
if(!vers){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3.0", test_version2: "3.0.8" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "3.0 - 3.0.8" );
	security_message( port: 0, data: report );
}

