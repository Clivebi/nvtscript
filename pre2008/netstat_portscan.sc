if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14272" );
	script_version( "2020-11-12T13:15:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "last_modification", value: "2020-11-12 13:15:01 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Netstat 'scanner'" );
	script_tag( name: "summary", value: "This plugin runs netstat to find open ports:

  - on the local machine by running the command

  - via SSH by using the provided credentials

  - by querying a possible exposed netstat service" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Michel Arboi" );
	script_family( "Port scanners" );
	script_dependencies( "gather-package-list.sc" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("port_service_func.inc.sc");
if( islocalhost() ) {
	buf = pread( cmd: "netstat", argv: make_list( "netstat",
		 "-a",
		 "-n" ) );
}
else {
	netstatPorts = service_get_ports( proto: "netstat", default_port_list: make_list( 15 ) );
	for netstatPort in netstatPorts {
		s = open_sock_tcp( netstatPort );
		if(s){
			for(;r = recv( socket: s, length: 4096 );){
				buf += r;
			}
			close( s );
			break;
		}
	}
	if(!ContainsString( buf, "LISTEN" )){
		port = kb_ssh_transport();
		if(port && get_port_state( port )){
			sock = ssh_login_or_reuse_connection();
			if(sock){
				buf = ssh_cmd( socket: sock, cmd: "cmd /c netstat -an", timeout: 60 );
				if(!ContainsString( buf, "LISTENING" ) && !ContainsString( buf, "0.0.0.0:0" ) && !ContainsString( buf, "*.*" )){
					buf = ssh_cmd( socket: sock, cmd: "netstat -a -n", timeout: 60 );
					ssh_close_connection();
					if(!buf){
						exit( 0 );
					}
				}
			}
		}
	}
}
ip = get_host_ip();
lines = split( buf );
n = max_index( lines );
if(n == 0){
	n = 1;
}
i = 0;
scanner_status( current: 0, total: n );
scanned = 0;
last_seen_proto = "";
check = ( !safe_checks() ) || ( ContainsString( get_preference( "unscanned_closed" ), "yes" ) );
identd_n = 0;
identd_err = 0;
for line in lines {
	v = eregmatch( pattern: "^[ \t]+(TCP|UDP)[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)[ \t]+(0\\.0\\.0\\.0:0|\\*\\.\\*)[ \t]+", string: line, icase: 0 );
	if(isnull( v )){
		v = eregmatch( pattern: "^(tcp|udp)[46]?[ \t]+.*[ \t]+(\\*|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)[:.]([0-9]+)[ \t]+(.*[ \t]+LISTEN|0\\.0\\.0\\.0:\\*)", string: line, icase: 1 );
	}
	if(isnull( v )){
		v = eregmatch( pattern: "^(tcp|udp)[ \t]+.*[ \t]+(:::)([0-9]+)[ \t]+.*[ \t]+LISTEN", string: line, icase: 1 );
	}
	if(isnull( v )){
		if(last_seen_proto){
			if( last_seen_proto == "udp" ) {
				v = eregmatch( pattern: "^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+Idle", string: line );
			}
			else {
				v = eregmatch( pattern: "^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+\\*\\.\\*[ \t]+.*(Idle|LISTEN)", string: line );
			}
			if(!isnull( v )){
				v[3] = v[2];
				v[2] = v[1];
				v[1] = last_seen_proto;
			}
		}
		if(isnull( v )){
			v = eregmatch( pattern: "^(TCP|UDP): +IPv4[ \t\r\n]*$", string: line );
			if(!isnull( v )){
				last_seen_proto = tolower( v[1] );
				v = NULL;
			}
		}
	}
	if(!isnull( v )){
		if(check){
			identd_soc = open_sock_tcp( 113 );
		}
		proto = tolower( v[1] );
		addr = v[2];
		port = v[3];
		if( int( port ) < 1 || int( port ) > 65535 ){
			}
		else {
			if(( check && addr != "127.0.0.1" ) || addr == "0.0.0.0" || addr == ip || addr == ":::" || addr == "*"){
				if( check && proto == "tcp" ){
					soc = open_sock_tcp( port );
					if(soc){
						scanner_add_port( proto: proto, port: port );
						if(identd_soc){
							req = strcat( port, ",", get_source_port( soc ), "\r\n" );
							if( send( socket: identd_soc, data: req ) <= 0 ){
								close( identd_soc );
								identd_soc = NULL;
								identd_err++;
								id = NULL;
							}
							else {
								id = recv_line( socket: identd_soc, length: 1024 );
							}
							if(id){
								ids = split( buffer: id, sep: ":" );
								if(ids && ContainsString( ids[1], "USERID" )){
									identd_n++;
									set_kb_item( name: "ident/tcp/" + port, value: ids[3] );
									log_message( port: port, data: "identd reveals that this service is running as user " + ids[3] );
								}
							}
						}
						close( soc );
					}
				}
				else {
					scanner_add_port( proto: proto, port: port );
				}
			}
		}
		scanned++;
	}
	scanner_status( current: i++, total: n );
}
if(identd_soc){
	close( identd_soc );
}
if(scanned){
	set_kb_item( name: "Host/scanned", value: TRUE );
	set_kb_item( name: "Host/udp_scanned", value: TRUE );
	set_kb_item( name: "Host/full_scan", value: TRUE );
	set_kb_item( name: "Host/scanners/netstat", value: TRUE );
	if(identd_n && !identd_err){
		set_kb_item( name: "Host/ident_scanned", value: TRUE );
	}
}
scanner_status( current: n, total: n );
exit( 0 );

