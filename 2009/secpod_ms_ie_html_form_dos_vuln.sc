if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900303" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-03 15:40:18 +0100 (Tue, 03 Feb 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0341" );
	script_bugtraq_id( 33494 );
	script_name( "Microsoft Internet Explorer HTML Form Value DoS Vulnerability" );
	script_xref( name: "URL", value: "http://jplopezy.fortunecity.es/ietest.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/500472/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to crash the browser." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 7.0 and prior." );
	script_tag( name: "insight", value: "Browser fails to validate user supplied data via a long VALUE attribute in
  an INPUT element." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed Internet Explorer and is prone to Denial
  of Service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
exit( 0 );
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(IsMatchRegexp( ieVer, "^[5-7]\\..*" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

