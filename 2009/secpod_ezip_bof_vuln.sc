if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900525" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-24 05:22:25 +0100 (Tue, 24 Mar 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1028" );
	script_bugtraq_id( 34044 );
	script_name( "eZip Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8180" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/49148" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_ezip_detect.sc" );
	script_mandatory_keys( "eZip/Version" );
	script_tag( name: "impact", value: "Successful exploit will allow the attacker to execute arbitrary code on
  the system to cause the application to crash." );
	script_tag( name: "affected", value: "eZip version 3.0 and prior on Windows." );
	script_tag( name: "insight", value: "A boundary check error while processing specially crafted .zip compressed
  files leads to a stack based buffer overflow." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with eZip Wizard and is prone to buffer
  overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ezipVer = get_kb_item( "eZip/Version" );
if(!ezipVer){
	exit( 0 );
}
if(version_is_less_equal( version: ezipVer, test_version: "3.0" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

