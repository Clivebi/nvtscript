if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111035" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-09-03 16:00:00 +0200 (Thu, 03 Sep 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Microsoft Lync Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "RTC/banner" );
	script_tag( name: "summary", value: "The script sends a HTTP
  request to the server and attempts to identify Microsoft Lync Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(concl = egrep( string: banner, pattern: "Server: RTC/[56]\\.0", icase: FALSE )){
	version = "unknown";
	install = port + "/tcp";
	concl = chomp( concl );
	cpe = "cpe:/a:microsoft:lync";
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Microsoft Lync Server", version: version, install: install, cpe: cpe, concluded: concl ), port: port );
}
exit( 0 );

