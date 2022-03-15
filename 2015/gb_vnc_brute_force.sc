if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106056" );
	script_version( "2021-07-23T07:56:26+0000" );
	script_tag( name: "last_modification", value: "2021-07-23 07:56:26 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-12-10 09:59:19 +0700 (Thu, 10 Dec 2015)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_name( "VNC Brute Force Login" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Brute force attacks" );
	script_dependencies( "vnc_security_types.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/vnc", 5900 );
	script_mandatory_keys( "vnc/detected", "vnc/security_types/detected" );
	script_exclude_keys( "default_credentials/disable_brute_force_checks" );
	script_add_preference( name: "Passwords", type: "entry", value: "admin, vnc, test, password", id: 1 );
	script_tag( name: "summary", value: "Try to log in with given passwords via VNC protocol." );
	script_tag( name: "insight", value: "This script tries to authenticate to a VNC server with the
  passwords set in the password preference. It will also test and report if no authentication /
  password is required at all.

  Note: Some VNC servers have a blacklisting scheme that blocks IP addresses after five unsuccessful
  connection attempts for a period of time. The script will abort the brute force attack if it
  encounters that it gets blocked.

  Note as well that passwords can be max. 8 characters long." );
	script_tag( name: "solution", value: "Change the password to something hard to guess or enable
  password protection at all." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_brute_force_checks" )){
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(!defined_func( "DES" )){
	exit( 0 );
}
blockedReport = "Too many unsuccessful connection attempts are made which means the scanner IP got " + "blocked. Therefore the brute force check was aborted.";
func reverseBits( data ){
	var data;
	var len, j, rev, orig, i, result;
	len = strlen( data );
	if(len > 8){
		len = 8;
	}
	for(j = 0;j < len;j++){
		rev = 0;
		orig = ord( data[j] );
		for(i = 0;i < 8;i++){
			if(orig & ( 0x1 << i )){
				rev = rev | ( 0x80 >> i );
			}
		}
		result += raw_string( rev );
	}
	return result;
}
passwords = script_get_preference( name: "Passwords", id: 1 );
if(!passwords || passwords == ""){
	passwords = "admin, vnc, test, password";
}
pw_list = split( buffer: passwords, sep: ", ", keep: FALSE );
port = service_get_port( default: 5900, proto: "vnc" );
if(!security_types = get_kb_list( "vnc/" + port + "/security_types" )){
	exit( 0 );
}
security_types = sort( security_types );
for password in pw_list {
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	res = recv( socket: soc, length: 512, min: 12 );
	if(strlen( res ) < 12){
		close( soc );
		exit( 0 );
	}
	if(ContainsString( res, "Too many security failures" )){
		log_message( data: blockedReport, port: port );
		close( soc );
		exit( 0 );
	}
	v = eregmatch( string: res, pattern: "^RFB ([0-9]+)\\.([0-9]+)\n" );
	if(isnull( v )){
		close( soc );
		exit( 0 );
	}
	major = int( v[1] );
	minor = int( v[2] );
	if(major < 3){
		close( soc );
		exit( 0 );
	}
	send( socket: soc, data: res );
	if( major == 3 && minor >= 3 && minor < 7 ){
		res = recv( socket: soc, min: 4, length: 4 );
		if(strlen( res ) != 4){
			close( soc );
			exit( 0 );
		}
	}
	else {
		if( major > 3 || minor >= 7 ){
			res = recv( socket: soc, min: 1, length: 1 );
			if(strlen( res ) < 1){
				close( soc );
				exit( 0 );
			}
			n = ord( res );
			if( n == 0 ){
				close( soc );
				exit( 0 );
			}
			else {
				for(i = 0;i < n;i++){
					res = recv( socket: soc, min: 1, length: 1 );
					if(strlen( res ) < 1){
						break;
					}
				}
			}
		}
		else {
			close( soc );
			exit( 0 );
		}
	}
	auth = FALSE;
	for type in security_types {
		if(type == 1){
			report = "No authentication is required to log in (Security Type NONE)";
			security_message( port: port, data: report );
			close( soc );
			exit( 0 );
		}
		if(type == 2){
			auth = TRUE;
			break;
		}
	}
	if( auth ){
		if(major > 3 || minor >= 7){
			send( socket: soc, data: raw_string( 0x02 ) );
		}
		challenge = recv( socket: soc, min: 16, length: 16 );
		if(!challenge || strlen( challenge ) != 16){
			close( soc );
			exit( 0 );
		}
		if(ContainsString( challenge, "Too many aut" ) || ContainsString( challenge, "Too many sec" )){
			log_message( data: blockedReport, port: port );
			close( soc );
			exit( 0 );
		}
		pw = reverseBits( data: password );
		padded_pw = pw;
		for(;strlen( padded_pw ) < 8;){
			padded_pw = padded_pw + raw_string( 0x00 );
		}
		chall_res = DES( challenge, padded_pw );
		send( socket: soc, data: chall_res );
		res = recv( socket: soc, min: 4, length: 4 );
		close( soc );
		if(!res || strlen( res ) != 4){
			continue;
		}
		auth_res = ord( res[3] );
		if(auth_res == 0){
			report = "It was possible to connect to the VNC server with the password: " + password;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	else {
		close( soc );
	}
}
exit( 0 );
