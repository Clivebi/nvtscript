if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800406" );
	script_version( "2020-10-22T06:41:10+0000" );
	script_tag( name: "last_modification", value: "2020-10-22 06:41:10 +0000 (Thu, 22 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-01-13 15:40:34 +0100 (Tue, 13 Jan 2009)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-0071" );
	script_bugtraq_id( 33154 );
	script_name( "Firefox Browser designMode Null Pointer Dereference DoS Vulnerability - Linux" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2009-01/0220.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2009-01/0223.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2009-01/0224.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_tag( name: "impact", value: "Successful remote exploitation could result in denying the service." );
	script_tag( name: "affected", value: "Firefox version 3.x to 3.0.5 on Linux." );
	script_tag( name: "insight", value: "Null pointer dereferencing error occurs in the browser which fails to validate
  the user input data when designMode module is enabled. These can be exploited
  via replaceChild or removeChild call, followed by a queryCommandValue,
  queryCommandState or queryCommandIndeterm call." );
	script_tag( name: "solution", value: "Upgerade to Firefox version 3.6.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
  to denial of service vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Linux/Ver" );
if(!ffVer){
	exit( 0 );
}
if(version_in_range( version: ffVer, test_version: "3.0", test_version2: "3.0.5" )){
	report = report_fixed_ver( installed_version: ffVer, vulnerable_range: "3.0 - 3.0.5" );
	security_message( port: 0, data: report );
}

