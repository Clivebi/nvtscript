if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900891" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3943" );
	script_name( "Microsoft Internet Denial Of Service Vulnerability - Nov09" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3658/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/507731/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/EXE/Ver" );
	script_tag( name: "impact", value: "Successful attacks may result in Denial of Service condition on
  the affected application." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 6.0 to 6.0.2900.2180 and 7.0 to 7.0.6000.16711." );
	script_tag( name: "insight", value: "An error exists when a JavaScript loop that configures the home
  page by using the 'setHomePage' method and a 'DHTML' behavior property. This
  can be exploited to cause an application hang." );
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
ieVer = get_kb_item( "MS/IE/EXE/Ver" );
if(!ieVer){
	exit( 0 );
}
if(version_in_range( version: ieVer, test_version: "6.0", test_version2: "6.0.2900.2180" ) || version_in_range( version: ieVer, test_version: "7.0", test_version2: "7.0.6000.16711" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

