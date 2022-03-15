if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800902" );
	script_version( "$Revision: 12629 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-2350" );
	script_bugtraq_id( 35570 );
	script_name( "Microsoft Internet Explorer XSS Vulnerability - July09" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3275" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/504718/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/504723/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary
code in the context of the application and to steal cookie-based
authentication credentials and other sensitive data." );
	script_tag( name: "affected", value: "Internet Explorer 6.0.2900.2180 and prior." );
	script_tag( name: "insight", value: "The flaw occurs because IE does not block Javascript URIs in
Refresh headers in HTTP responses which may be exploited via vectors related
to injecting a Refresh header or specifying the content of a Refresh header." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Internet Explorer and is prone to
Cross-Site Scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(version_is_less_equal( version: ieVer, test_version: "6.0.2900.2180" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

