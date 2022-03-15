if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100517" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-03-06 09:57:46 +0100 (Sat, 06 Mar 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Informix Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "find_service2.sc" );
	script_require_ports( "Services/unknown", 9088 );
	script_tag( name: "summary", value: "IBM Informix RDBMS is running at this port." );
	script_xref( name: "URL", value: "http://www-01.ibm.com/software/data/informix/" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("byte_func.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Informix Detection";
username = "OPENVAS";
attempt = 3;
func read_data( data, pos ){
	var pos, data, str;
	var len;
	if(strlen( data ) < pos){
		return FALSE;
	}
	if(!l = substr( data, pos, pos )){
		return FALSE;
	}
	len = ord( l[0] );
	if( str = substr( data, pos + 1, pos + 1 + len - 2 ) ){
		return str;
	}
	else {
		return FALSE;
	}
}
port = unknownservice_get_port( default: 9088 );
soc = open_sock_tcp( port );
if(soc){
	req = raw_string( "sqAYABPQAAsqlexec ", username, " -p", username, " 9.350  ", "AAA#B000000 ", "-d", username, " -fIEEEI ", "DBPATH=//", username, " DBMONEY=$. ", "CLIENT_LOCALE=en_US.8859-1 ", "SINGLELEVEL=no ", "LKNOTIFY=yes ", "LOCKDOWN=no ", "NODEFDAC=no ", "CLNT_PAM_CAPABLE=1 ", ":AG0AAAA9b24AAAAAAAAAAAA9c29jdGNwAAAAAAABAAABPAAAAAAAAAAAc3FsZXh", "lYwAAAAAAAAVzcWxpAAALAAAAAwAJbXlzZXJ2ZXIAAGsAAAAAAABSjQAAAAAABWt", "pcmEAAAwvZGV2L3B0cy8xMgAACy9ob21lL21pbWUAAHQACAAAA.gAAABkAH8=", 0x00 );
	for(;!buf && attempt--;){
		send( socket: soc, data: req );
		buf = recv( socket: soc, length: 2048 );
	}
	close( soc );
	if(strlen( buf ) > 1 && strlen( buf ) == getword( blob: buf, pos: 0 ) && ContainsString( buf, "IEEEI" ) && ContainsString( buf, "lsrvinfx" )){
		service_register( port: port, proto: "informix", ipproto: "tcp" );
		register_host_detail( name: "App", value: NASLString( "cpe:/a:ibm:informix_dynamic_server" ), desc: SCRIPT_DESC );
		info = NASLString( "\\n\\nHere is the gathered data:\\n\\n" );
		data = strstr( buf, NASLString( raw_string( 0x00 ), "k", raw_string( 0x00 ) ) );
		pos = int( 15 );
		if(fqdn = read_data( data: data, pos: pos )){
			if(IsMatchRegexp( fqdn, "^[a-zA-Z0-9]" )){
				info += NASLString( "FQDN:         ", fqdn, "\\n" );
			}
		}
		pos += len + 2;
		if(host = read_data( data: data, pos: pos )){
			if(IsMatchRegexp( host, "^[a-zA-Z0-9]" )){
				info += NASLString( "Hostname:     ", host, "\\n" );
			}
		}
		pos += len + 2;
		if(install = read_data( data: data, pos: pos )){
			if(IsMatchRegexp( install, "^[/\\:a-zA-Z0-9]" )){
				info += NASLString( "PATH:         ", install, "\\n" );
			}
		}
		report = "";
		if(strlen( info ) > 35){
			report = info;
		}
		service_register( port: port, ipproto: "tcp", proto: "informix" );
		log_message( port: port, data: report );
	}
}
exit( 0 );

