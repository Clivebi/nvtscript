if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900897" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-4073" );
	script_bugtraq_id( 37117 );
	script_name( "Microsoft Internet Explorer PDF Information Disclosure Vulnerability - Nov09" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/508010/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.theregister.co.uk/2009/11/23/internet_explorer_file_disclosure_bug/" );
	script_xref( name: "URL", value: "http://securethoughts.com/2009/11/millions-of-pdf-invisibly-embedded-with-your-internal-disk-paths/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful attacks which may leads to the exposure of system
  information on the affected system." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 6/7/8." );
	script_tag( name: "insight", value: "The weakness is due to an Internet Explorer including the first
  63 bytes of the file path in the 'Title' property when converting local HTML or
  MHT files to PDF using a PDF printer. This can lead to the exposure of certain
  system information e.g. the user name." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Internet Explorer and is prone to
  Information Disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(IsMatchRegexp( ieVer, "^(6|7|8)\\..*" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

