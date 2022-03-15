if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103694" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-04-11 09:34:17 +0200 (Thu, 11 Apr 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Tandberg Devices Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/tandberg/device/detected" );
	script_tag( name: "summary", value: "Detection of Tandberg Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a Tandberg device and extract the codec release from
  the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
buf = telnet_get_banner( port: port );
if(!buf || !ContainsString( buf, "TANDBERG Codec Release" )){
	exit( 0 );
}
vers = NASLString( "unknown" );
install = port + "/tcp";
version = eregmatch( string: buf, pattern: NASLString( "TANDBERG Codec Release ([^\\r\\n]+)" ), icase: TRUE );
if(!isnull( version[1] )){
	vers = version[1];
}
set_kb_item( name: "host_is_tandberg_device", value: TRUE );
set_kb_item( name: "tandberg_codec_release", value: vers );
cpe = "cpe:/h:tandberg:*";
register_product( cpe: cpe, location: install, port: port, service: "telnet" );
message = "The remote Host is a Tandberg Device.\nCodec Release: " + vers + "\nCPE: " + cpe + "\nConcluded: " + buf + "\n";
log_message( data: message, port: port );
exit( 0 );

