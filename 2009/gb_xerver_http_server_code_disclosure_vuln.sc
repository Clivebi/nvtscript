if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801019" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-21 10:12:07 +0200 (Wed, 21 Oct 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-3544" );
	script_bugtraq_id( 36454 );
	script_name( "Xerver HTTP Server Source Code Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36681" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9649" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xerver_http_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "xerver/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to gain sensitive
  information about the application." );
	script_tag( name: "affected", value: "Xerver version 4.32 and prior on all platforms." );
	script_tag( name: "insight", value: "An error exists when processing HTTP requests containing '::$DATA'
  after the HTML file name which can be exploited to disclose the source code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Xerver HTTP Server and is prone to the Source
  Code Disclosure Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
xerPort = http_get_port( default: 80 );
xerVer = get_kb_item( "www/" + xerPort + "/Xerver" );
if(xerVer != NULL){
	if(version_is_less_equal( version: xerVer, test_version: "4.32" )){
		security_message( xerPort );
	}
}

