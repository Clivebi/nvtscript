if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105483" );
	script_version( "2021-02-12T06:42:15+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-12 06:42:15 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2015-12-11 15:21:49 +0100 (Fri, 11 Dec 2015)" );
	script_name( "SSL/TLS: TLS_FALLBACK_SCSV Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_tls_version_get.sc" );
	script_mandatory_keys( "ssl_tls/port" );
	script_tag( name: "summary", value: "This script reports if TLS_FALLBACK_SCSV is enabled or not." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("mysql.inc.sc");
require("ssl_funcs.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("byte_func.inc.sc");
func _check_tls_fallback_scsv( port, ssl_ver ){
	var hello, soc, hdr, len, pay, len1, next, mult, hello_done, port, ssl_ver;
	hello = ssl_hello( port: port, version: ssl_ver, add_tls_fallback_scsv: TRUE );
	soc = open_ssl_socket( port: port );
	if(!soc){
		return FALSE;
	}
	send( socket: soc, data: hello );
	for(;!hello_done;){
		hdr = recv( socket: soc, length: 5, timeout: 5 );
		if(!hdr || strlen( hdr ) != 5){
			close( soc );
			return FALSE;
		}
		len = getword( blob: hdr, pos: 3 );
		pay = recv( socket: soc, length: len, timeout: 5 );
		if(!pay){
			close( soc );
			return FALSE;
		}
		if(ord( hdr[0] ) == SSLv3_ALERT){
			if(strlen( pay ) < 2){
				close( soc );
				return FALSE;
			}
			if(ord( pay[1] ) == SSLv3_ALERT_INAPPROPRIATE_FALLBACK){
				close( soc );
				return TRUE;
			}
		}
		if(ord( pay[0] ) == 13 && ord( hdr[0] ) == 22){
			len1 = getword( blob: pay, pos: 2 );
			next = substr( pay, len1 + 4 );
			if(next && ord( next[0] ) == 14){
				hello_done = TRUE;
				close( soc );
				return FALSE;
			}
		}
		if(( strlen( pay ) - 4 ) > 0){
			mult = substr( pay, ( strlen( pay ) - 4 ), strlen( pay ) );
		}
		if(( ord( pay[0] ) == 14 || ( mult && ord( mult[0] ) == 14 ) ) && ord( hdr[0] ) == 22){
			hello_done = TRUE;
			close( soc );
			return FALSE;
		}
	}
	close( soc );
	return FALSE;
}
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
ssl_ver = SSL_v3;
if(_check_tls_fallback_scsv( port: port, ssl_ver: ssl_ver )){
	report = "It was determined that the remote TLSv1.0+ service supports the TLS_FALLBACK_SCSV and is therefore not affected by downgrading attacks like the POODLE vulnerability.";
	set_kb_item( name: "tls_fallback_scsv_supported/" + port, value: TRUE );
	exit( 99 );
}
report = "It was determined that the remote TLSv1.0+ service does not support the TLS_FALLBACK_SCSV and might be affected by downgrading attacks like the POODLE vulnerability.";
exit( 0 );

