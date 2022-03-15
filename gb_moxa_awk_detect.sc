if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106740" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2017-04-11 13:52:39 +0200 (Tue, 11 Apr 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Moxa AWK Series Devices Detection" );
	script_tag( name: "summary", value: "Detection of Moxa AWK Series Devices (Industrial Wireless LAN Solutions).

  The script sends a connection request to the server and attempts to detect Moxa AWK Series Devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_goahead_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "embedthis/goahead/detected" );
	script_xref( name: "URL", value: "http://www.moxa.com/product/Industrial_Wireless_LAN.htm" );
	exit( 0 );
}
CPE = "cpe:/a:embedthis:goahead";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/Login.asp" );
if(ContainsString( res, "<title>Moxa AWK-" ) && ContainsString( res, "Password508=" ) && ContainsString( res, "llogin.gif" )){
	version = "unknown";
	mod = eregmatch( pattern: "Moxa (AWK-[^ ]+)", string: res );
	if(isnull( mod[1] )){
		exit( 0 );
	}
	model = mod[1];
	set_kb_item( name: "moxa_awk/detected", value: TRUE );
	set_kb_item( name: "moxa_awk/model", value: model );
	cpe = "cpe:/h:moxa:" + tolower( model );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: "The remote host is a Moxa " + model + "\n\nCPE: " + cpe, port: port );
	exit( 0 );
}
exit( 0 );

