if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11124" );
	script_version( "2021-03-22T07:55:33+0000" );
	script_tag( name: "last_modification", value: "2021-03-22 07:55:33 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "MLDonkey Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Product detection" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/mldonkey-telnet", 4000 );
	script_tag( name: "summary", value: "Telnet based detection of MLDonkey." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 4000, proto: "mldonkey-telnet" );
r = telnet_get_banner( port: port );
if(!r){
	exit( 0 );
}
if(ContainsString( r, "Welcome on mldonkey command-line" )){
	log_message( port: port );
}
exit( 0 );

