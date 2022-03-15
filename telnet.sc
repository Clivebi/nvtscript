if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100074" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Telnet Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service6.sc", "secpod_open_tcp_ports.sc" );
	script_require_ports( 23, 992, 1953, 2323, 5000, 9999, 41795, "TCP/PORTS" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc854" );
	script_tag( name: "summary", value: "This scripts tries to detect a Telnet service running
  at the remote host." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("telnet_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("http_func.inc.sc");
require("dump.inc.sc");
require("misc_func.inc.sc");
default_ports = make_list( 23,
	 992,
	 1953,
	 2323,
	 5000,
	 9999,
	 41795 );
all_tcp_ports = tcp_get_all_ports();
if( all_tcp_ports ) {
	ports = make_list( default_ports,
		 all_tcp_ports );
}
else {
	ports = default_ports;
}
telnet_ports = telnet_get_ports();
ports = nasl_make_list_unique( ports, telnet_ports );
unknown_ports = unknownservice_get_ports( nodefault: TRUE );
if(!unknown_ports || !is_array( unknown_ports )){
	unknown_ports = make_list();
}
for port in ports {
	if(!get_port_state( port )){
		continue;
	}
	if(!service_verify( port: port, proto: "telnet" ) && !service_is_unknown( port: port )){
		continue;
	}
	if(!in_array( search: port, array: default_ports, part_match: FALSE ) && in_array( search: port, array: unknown_ports, part_match: FALSE )){
		continue;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		sleep( 2 );
		soc = open_sock_tcp( port );
		if(!soc){
			continue;
		}
	}
	banner = "";
	max_retry = 2;
	curr_retry = 0;
	for(;TRUE;){
		n++;
		res = recv( socket: soc, length: 1, timeout: 10 );
		if(!res){
			if(curr_retry > max_retry){
				break;
			}
			curr_retry++;
			continue;
		}
		banner += res;
		if(n > 50){
			break;
		}
	}
	close( soc );
	if(!banner || strlen( banner ) < 3){
		continue;
	}
	if(ord( banner[0] ) != 255 || ord( banner[1] ) < 240 || ord( banner[1] ) > 254){
		continue;
	}
	if(ContainsString( banner, "VxWorks login:" )){
		telnet_set_banner( port: port, banner: bin2string( ddata: banner, noprint_replacement: " " ) );
	}
	log_message( port: port, data: "A Telnet server seems to be running on this port" );
	if(service_is_unknown( port: port )){
		service_register( port: port, proto: "telnet", message: "A Telnet server seems to be running on this port" );
	}
}
exit( 0 );

