if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800337" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-0072" );
	script_bugtraq_id( 33149 );
	script_name( "Microsoft Internet Explorer NULL Pointer DoS Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/47788" );
	script_xref( name: "URL", value: "http://skypher.com/index.php/2009/01/07/msie-screen-null-ptr-dos-details/" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause the application
  to crash." );
	script_tag( name: "affected", value: "Microsoft, Internet Explorer version 6.0, 7.0, 8.0 Beta2 and prior." );
	script_tag( name: "insight", value: "The flaw is due to improper handling of onload=screen[''] attribute
  value in BODY element. By persuading a victim to visit a specially-crafted
  Web page, denial of service can be caused." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host has Internet Explorer installed and is prone to Remote
  Denial of Service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(version_in_range( version: ieVer, test_version: "6.0", test_version2: "8.0.6001.18241" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

