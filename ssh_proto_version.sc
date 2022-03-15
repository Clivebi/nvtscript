if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100259" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-08-25 21:06:41 +0200 (Tue, 25 Aug 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SSH Protocol Versions Supported" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_algos.sc", "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_tag( name: "summary", value: "Identification of SSH protocol versions supported by the remote
  SSH Server. Also reads the corresponding fingerprints from the service.

  The following versions are tried: 1.33, 1.5, 1.99 and 2.0" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
vt_strings = get_vt_strings();
func read_key( key, setKB, port ){
	var key, setKB, port;
	var key_hex, len, x, fingerprint;
	key_hex = hexstr( MD5( key ) );
	len = strlen( key_hex );
	for(x = 0;x < len;x += 2){
		fingerprint += substr( key_hex, x, x + 1 );
		if(x + 2 < len){
			fingerprint += ":";
		}
	}
	if(setKB){
		set_kb_item( name: "SSH/fingerprints/available", value: TRUE );
		if( ContainsString( key, "ssh-rsa" ) ){
			set_kb_item( name: "SSH/" + port + "/fingerprint/ssh-rsa", value: fingerprint );
		}
		else {
			if(ContainsString( key, "ssh-dss" )){
				set_kb_item( name: "SSH/" + port + "/fingerprint/ssh-dss", value: fingerprint );
			}
		}
	}
	return fingerprint;
}
func get_fingerprint( version, port ){
	var version, port;
	var buf, header, fingerprint, key, len, soc, algo, rep, key64, sess_id, algos, tmpAlgoList, kb_algos, ka;
	if( version == "2.0" ){
		algos = make_list();
		tmpAlgoList = make_list();
		kb_algos = get_kb_list( "ssh/" + port + "/server_host_key_algorithms" );
		if(kb_algos){
			for ka in kb_algos {
				algos = make_list( algos,
					 ka );
			}
		}
		if(!algos){
			algos = ssh_host_key_algos;
		}
		for algo in algos {
			soc = open_sock_tcp( port );
			if(!soc){
				return FALSE;
			}
			ssh_login( socket: soc, keytype: algo );
			sess_id = ssh_session_id_from_sock( soc );
			if(!sess_id){
				close( soc );
				continue;
			}
			key = ssh_get_server_host_key( sess_id: sess_id );
			close( soc );
			if(!ContainsString( key, algo )){
				continue;
			}
			fingerprint = read_key( key: key, port: port );
			key64 = base64( str: key );
			set_kb_item( name: "SSH/fingerprints/available", value: TRUE );
			set_kb_item( name: "SSH/" + port + "/fingerprint/" + algo, value: fingerprint );
			set_kb_item( name: "SSH/" + port + "/publickey/" + algo, value: key64 );
			register_host_detail( name: "ssh-key", value: port + " " + algo + " " + key64, desc: "SSH Key" );
			tmpAlgoList = make_list( tmpAlgoList,
				 algo + ": " + fingerprint );
		}
		tmpAlgoList = sort( tmpAlgoList );
		for tmpAlgo in tmpAlgoList {
			rep += "\n" + tmpAlgo;
		}
		return rep;
	}
	else {
		if( version == "1.5" ){
			soc = open_sock_tcp( port );
			if(!soc){
				return FALSE;
			}
			buf = recv_line( socket: soc, length: 8192 );
			send( socket: soc, data: "SSH-1.5-" + vt_strings["default"] + "_1.0\n" );
			header = recv( socket: soc, length: 4 );
			if(strlen( header ) < 4){
				return FALSE;
			}
			len = ord( header[2] ) * 256 + ord( header[3] );
			buf = recv( socket: soc, length: len );
			if(!buf){
				return FALSE;
			}
			buf = header + buf;
			close( soc );
			if(!key = substr( buf, 132, 259 ) + raw_string( 0x23 )){
				return FALSE;
			}
			if( fingerprint = read_key( key: key, setKB: TRUE, port: port ) ){
				return fingerprint;
			}
			else {
				return FALSE;
			}
		}
		else {
			close( soc );
			return FALSE;
		}
	}
	return fingerprint;
}
versions = make_list( "0.12",
	 "1.33",
	 "1.5",
	 "1.99",
	 "2.0" );
port = ssh_get_port( default: 22 );
var random_ver_response;
for version in versions {
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	ret = recv_line( socket: soc, length: 512 );
	if(!ret){
		close( soc );
		exit( 0 );
	}
	if(!egrep( pattern: "^SSH-.+", string: ret )){
		close( soc );
		return ( 0 );
	}
	request = NASLString( "SSH-", version, "-", vt_strings["default"], "SSH_1.0\\n" );
	send( socket: soc, data: request );
	ret = recv_line( socket: soc, length: 500 );
	close( soc );
	if(!ret){
		continue;
	}
	if(!egrep( pattern: "Protocol.*differ", string: ret ) && !ContainsString( ret, "The connection is closed by SSH Server" )){
		if(version == "0.12"){
			random_ver_response = TRUE;
			version = "2.0";
		}
		supported_versions[version] = version;
		set_kb_item( name: "SSH/supportedversions/" + port, value: version );
		if(random_ver_response){
			break;
		}
	}
}
if(supported_versions){
	supported_versions = sort( supported_versions );
	for supported in supported_versions {
		if(supported == "2.0" || supported == "1.5"){
			if(fingerprint = get_fingerprint( version: supported, port: port )){
				if( supported == "2.0" ){
					fingerprint_info += "\nSSHv2 Fingerprint(s):" + fingerprint;
				}
				else {
					if(supported == "1.5"){
						fingerprint_info += "\nSSHv1 Fingerprint: " + fingerprint;
					}
				}
			}
		}
		info += NASLString( "\\n", chomp( supported ) );
	}
	if(fingerprint_info){
		info += NASLString( "\\n", fingerprint_info );
	}
	set_kb_item( name: "SSH/supportedversions/available", value: TRUE );
	if(random_ver_response){
		info += "\n\nNote: The remote SSH service is accepting the non-existent SSH Protocol Version 0.12. Because of this behavior it is not possible to fingerprint";
		info += " the exact supported SSH Protocol Version. Based on this support for SSH Protocol Version 2.0 only is assumed.";
	}
	log_message( port: port, data: "The remote SSH Server supports the following SSH Protocol Versions:" + info );
}
exit( 0 );

