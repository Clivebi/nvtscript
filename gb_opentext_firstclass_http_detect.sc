if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113606" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-02 12:00:00 +0200 (Mon, 02 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenText FirstClass Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "firstclass/banner" );
	script_tag( name: "summary", value: "Checks whether OpenText FirstClass is present on
  the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://www.opentext.com/products-and-solutions/products/specialty-technologies/firstclass" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_remote_headers( port: port );
if(IsMatchRegexp( buf, "Server: *FirstClass" )){
	replace_kb_item( name: "opentext/firstclass/detected", value: TRUE );
	set_kb_item( name: "opentext/firstclass/http/detected", value: TRUE );
	set_kb_item( name: "opentext/firstclass/http/port", value: port );
	ver = eregmatch( string: buf, pattern: "FirstClass/([0-9.]+)" );
	if(!isnull( ver[1] )){
		set_kb_item( name: "opentext/firstclass/http/concluded", value: ver[0] );
		set_kb_item( name: "opentext/firstclass/http/version", value: ver[1] );
	}
}
exit( 0 );

