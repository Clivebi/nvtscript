if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801349" );
	script_version( "2020-06-09T10:15:40+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 10:15:40 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)" );
	script_cve_id( "CVE-2010-2118" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Microsoft Internet Explorer 'IFRAME' Denial Of Service Vulnerability (June-10)" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/4238/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/511509/100/0/threaded" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a
  denial of service." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 6.0.2900.2180/8.0.7600.16385 and prior." );
	script_tag( name: "insight", value: "The flaw is due to improper handling of an 'JavaScript' code
  which contains an infinite loop, that creates IFRAME elements for invalid news:// URIs." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Internet Explorer and is prone to
  Denial Of Service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(version_in_range( version: ieVer, test_version: "6.0", test_version2: "6.0.2900.2180" ) || version_in_range( version: ieVer, test_version: "8.0", test_version2: "8.0.7600.16385" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

