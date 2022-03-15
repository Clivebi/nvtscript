if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103891" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-01-27 13:32:54 +0100 (Mon, 27 Jan 2014)" );
	script_name( "Cisco TelePresence Detection (FTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "gb_cisco_telepresence_detect_snmp.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/cisco/telepresence/detected" );
	script_exclude_keys( "cisco/telepresence/version", "cisco/telepresence/typ" );
	script_tag( name: "summary", value: "The script sends a connection request to
  the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(get_kb_item( "cisco/telepresence/typ" )){
	if(get_kb_item( "cisco/telepresence/version" )){
		exit( 0 );
	}
}
cisport = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: cisport );
if(!banner || !IsMatchRegexp( banner, "Welcome to the (Cisco TelePresence|Codian) MCU" )){
	exit( 0 );
}
typ = "unknown";
t = eregmatch( pattern: "((Cisco TelePresence|Codian) MCU [^,]+)", string: banner );
if(!isnull( t[1] )){
	typ = t[1];
}
version = "unknown";
s = eregmatch( pattern: ", version (.*)$", string: banner );
if(!isnull( s[1] )){
	version = chomp( s[1] );
}
set_kb_item( name: "cisco/telepresence/typ", value: typ );
set_kb_item( name: "cisco/telepresence/version", value: version );
cpe = "cpe:/a:cisco:telepresence_mcu_mse_series_software:" + tolower( version );
register_product( cpe: cpe, location: cisport + "/tcp", port: cisport, service: "ftp" );
log_message( data: build_detection_report( app: typ, version: version, install: cisport + "/tcp", cpe: cpe, concluded: banner ), port: cisport );
exit( 0 );

