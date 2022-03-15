if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801100" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-09 13:17:56 +0100 (Sat, 09 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "NaviCOPA Server Version Detection" );
	script_family( "Product detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "NaviCOPA/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "This script detects the version of installed NaviCOPA Server." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "NaviCOPA Server Version Detection";
httpPort = http_get_port( default: 80 );
banner = http_get_remote_headers( port: httpPort );
if(ContainsString( banner, "NaviCOPA" )){
	ncpaVer = eregmatch( pattern: "Version ([0-9.]+)", string: banner );
	if(!isnull( ncpaVer[1] )){
		set_kb_item( name: "NaviCOPA/" + httpPort + "/Ver", value: ncpaVer[1] );
		set_kb_item( name: "navicopa/detected", value: TRUE );
		log_message( data: "NaviCOPA Server version " + ncpaVer[1] + " was detected on the host" );
		cpe = build_cpe( value: ncpaVer[1], exp: "^([0-9.]+)", base: "cpe:/a:intervations:navicopa_web_server:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}

