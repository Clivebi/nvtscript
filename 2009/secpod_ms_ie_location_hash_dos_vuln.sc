if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900826" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-2954" );
	script_name( "Microsoft Internet Explorer 'location.hash' DOS Vulnerability" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3424/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/506006/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation lets the attacker cause memory or CPU
  consumption, resulting in Denial of Service condition." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 6.0.2900.2180 and prior." );
	script_tag( name: "insight", value: "Error exists when application fails to handle JavaScript code
  with a long string value for the hash property aka 'location.hash'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Internet Explorer and is prone to
  Denial of Service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
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

