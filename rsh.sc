if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108478" );
	script_version( "2021-04-16T08:08:22+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 08:08:22 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-03-26 19:23:59 +0100 (Thu, 26 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "rsh Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service1.sc" );
	script_require_ports( "Services/rsh", "Services/unknown", 514 );
	script_tag( name: "summary", value: "Checks if the remote host is running a rsh service.

  Note: The reporting takes place in a separate VT 'rsh Unencrypted Cleartext Login'
  (OID: 1.3.6.1.4.1.25623.1.0.100080)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("dump.inc.sc");
data = NASLString( "0\0", "root", "\0", "root", "\0", "id\0" );
ports = make_list( 514 );
unkn_ports = unknownservice_get_ports( default_port_list: make_list( 514 ) );
if(unkn_ports && is_array( unkn_ports )){
	ports = make_list( ports,
		 unkn_ports );
}
rsh_ports = service_get_ports( default_port_list: make_list( 514 ), proto: "rsh" );
if(rsh_ports && is_array( rsh_ports )){
	ports = make_list( ports,
		 rsh_ports );
}
ports = nasl_make_list_unique( ports );
for port in ports {
	found = FALSE;
	if(!get_port_state( port )){
		continue;
	}
	if(!soc = open_priv_sock_tcp( dport: port )){
		continue;
	}
	send( socket: soc, data: data );
	buf = recv( socket: soc, length: 8192 );
	close( soc );
	if(!buf){
		continue;
	}
	if( ContainsString( buf, "Permission denied" ) ){
		found = TRUE;
		report = "The rsh service is not allowing connections from this host.";
	}
	else {
		if( egrep( pattern: "uid=[0-9]+.*gid=[0-9]+.*", string: bin2string( ddata: buf ) ) ){
			found = TRUE;
			set_kb_item( name: "rsh/login_from", value: "root" );
			set_kb_item( name: "rsh/login_to", value: "root" );
			report = "The rsh service is misconfigured so it is allowing conntections without a password or with default root:root credentials.";
		}
		else {
			if(ContainsString( buf, "getnameinfo: Temporary failure in name resolution" )){
				found = TRUE;
				report = "The rsh service currently has issues with name resolution and is not allowing connections from this host.";
			}
		}
	}
	if(found){
		set_kb_item( name: "rsh/detected", value: TRUE );
		set_kb_item( name: "rsh/" + port + "/detected", value: TRUE );
		set_kb_item( name: "rsh/" + port + "/service_report", value: report );
		service_register( port: port, proto: "rsh", message: "A rsh service seems to be running on this port." );
		log_message( port: port, data: "A rsh service is running at this port." );
	}
}
exit( 0 );

