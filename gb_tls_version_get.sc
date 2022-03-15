if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105782" );
	script_version( "2021-02-12T06:42:15+0000" );
	script_tag( name: "last_modification", value: "2021-02-12 06:42:15 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-06-29 10:54:20 +0200 (Wed, 29 Jun 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "secpod_open_tcp_ports.sc", "gb_starttls_pop3.sc", "gb_starttls_imap.sc", "gb_starttls_ftp.sc", "gb_starttls_smtp.sc", "gb_postgres_tls_support.sc", "gb_starttls_ldap.sc", "gb_starttls_nntp.sc", "gb_starttls_xmpp.sc", "gb_starttls_mysql.sc", "gb_starttls_irc.sc", "gb_starttls_rdp.sc", "gb_dont_scan_fragile_device.sc" );
	script_mandatory_keys( "TCP/PORTS" );
	script_add_preference( name: "Seconds to wait between probes", value: "", type: "entry", id: 1 );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the SSL/TLS version number from the reply. The Result is stored in the KB." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("mysql.inc.sc");
require("ssl_funcs.inc.sc");
require("byte_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
func get_tls_hello_record( vers, port, use_extended_ec, delay ){
	var vers, port, use_extended_ec, delay;
	var soc, hello, data, search, record;
	if(!vers || !port){
		return;
	}
	if(!soc = open_ssl_socket( port: port )){
		return;
	}
	if(!hello = ssl_hello( port: port, version: vers, use_extended_ec: use_extended_ec )){
		close( soc );
		return;
	}
	if( delay ) {
		sleep( delay );
	}
	else {
		usleep( 50000 );
	}
	send( socket: soc, data: hello );
	data = ssl_recv( socket: soc );
	close( soc );
	if(!data){
		return;
	}
	if( vers == SSL_v2 ) {
		search = make_array( "content_typ", SSLv2_SERVER_HELLO );
	}
	else {
		search = make_array( "handshake_typ", SSLv3_SERVER_HELLO );
	}
	if( !record = search_ssl_record( data: data, search: search ) ){
		if(vers == SSL_v2){
			return;
		}
		if( search_ssl_record( data: data, search: make_array( "content_typ", SSLv3_ALERT ) ) ) {
			return "alert_received";
		}
		else {
			return;
		}
	}
	else {
		return record;
	}
}
port = get_kb_item( "TCP/PORTS" );
if(!port || !get_port_state( port )){
	exit( 0 );
}
if(get_kb_item( "fragile_port/exclude_tls/" + port )){
	exit( 0 );
}
d = script_get_preference( name: "Seconds to wait between probes", id: 1 );
if(int( d ) > 0){
	delay = int( d );
}
sup_tls = "";
for vers in make_list( TLS_10,
	 TLS_11,
	 TLS_12,
	 SSL_v2,
	 SSL_v3 ) {
	extended_ec_used = "no";
	record = get_tls_hello_record( vers: vers, port: port, use_extended_ec: FALSE, delay: nil );
	if(!record || ( !is_array( record ) && record == "alert_received" )){
		if(vers == TLS_10 || vers == TLS_11 || vers == TLS_12){
			record = get_tls_hello_record( vers: vers, port: port, use_extended_ec: TRUE, delay: nil );
			extended_ec_used = "yes";
		}
		if(!record || ( !is_array( record ) && record == "alert_received" )){
			continue;
		}
	}
	if(vers == SSL_v2 && int( record["cipher_spec_len"] ) < 1){
		continue;
	}
	if(isnull( record["version"] )){
		continue;
	}
	if(record["version"] == vers){
		set_kb_item( name: "tls_version_get/" + port + "/version", value: version_string[vers] );
		set_kb_item( name: "tls_version_get/" + port + "/hex_version", value: hexstr( record["version"] ) );
		set_kb_item( name: "tls_version_get/" + port + "/raw_version", value: record["version"] );
		set_kb_item( name: "tls_version_get/" + port + "/extended_ec_used", value: extended_ec_used );
		set_kb_item( name: "tls_version_get/" + port + "/" + version_kb_string_mapping[vers] + "/extended_ec_used", value: extended_ec_used );
		sup_tls += version_string[vers] + ";";
	}
}
if(strlen( sup_tls )){
	sup_tls = ereg_replace( string: sup_tls, pattern: "(;)$", replace: "" );
	set_kb_item( name: "tls/supported/" + port, value: sup_tls );
	set_kb_item( name: "ssl_tls/port", value: port );
}
exit( 0 );

