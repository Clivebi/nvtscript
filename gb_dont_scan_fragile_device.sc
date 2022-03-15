if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108298" );
	script_version( "2021-03-05T10:52:42+0000" );
	script_tag( name: "last_modification", value: "2021-03-05 10:52:42 +0000 (Fri, 05 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-11-24 14:08:04 +0100 (Fri, 24 Nov 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Do not scan fragile devices or ports" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Settings" );
	script_dependencies( "global_settings.sc" );
	script_mandatory_keys( "global_settings/exclude_fragile" );
	script_add_preference( name: "Exclude specific port(s) from scan", type: "entry", value: "", id: 1 );
	script_tag( name: "summary", value: "This script checks if the remote host is a 'fragile' device
  known to be crashing / showing an unexpected behavior if scanned. It will output more info
  if a specific port or the whole device was excluded from the scan.

  Additionally the 'Exclude specific port(s) from scan' script preference allows to specify own ports
  to be exclude from the scan with the following syntax:

  5060:all:full,443:tcp:tlsonly

  where the following is allowed:

  5060 - portnumber between 1 and 65535

  all  - transport protocol of the port. Currently available options: all, tcp, udp

  full - how the port should be excluded. full: the port is excluded from all checks including SSL/TLS tests,
  tlsonly: the port is only excluded from SSL/TLS checks,
  nottls: the port is excluded from all checks except SSL/TLS. Currently available options: full, nottls, tlsonly

  It is possible to disable this behavior by setting the preference 'Exclude known fragile devices/ports from scan'
  within the 'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'no'." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ftp_func.inc.sc");
require("telnet_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
if(get_kb_item( "Host/scanned" ) == 0){
	exit( 0 );
}
if(!get_kb_item( "global_settings/exclude_fragile" )){
	exit( 0 );
}
func check_and_apply_exclude_port_definition( exclude_port_definition ){
	var exclude_port_definition, _split_list, _split_line, _error;
	var _split_item, _port, _proto, _tests, exclude_from_tls, only_exclude_from_tls;
	_split_list = split( buffer: exclude_port_definition, sep: ",", keep: FALSE );
	for _split_line in _split_list {
		if(!egrep( string: _split_line, pattern: "^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]):(all|tcp|udp):(full|nottls|tlsonly)$" )){
			_error += _split_line + "\n";
			continue;
		}
		_split_item = split( buffer: _split_line, sep: ":", keep: FALSE );
		_port = _split_item[0];
		_proto = _split_item[1];
		_tests = _split_item[2];
		if( _tests == "full" ){
			exclude_from_tls = TRUE;
			only_exclude_from_tls = FALSE;
		}
		else {
			if( _tests == "nottls" ){
				exclude_from_tls = FALSE;
				only_exclude_from_tls = FALSE;
			}
			else {
				if(_tests == "tlsonly"){
					exclude_from_tls = TRUE;
					only_exclude_from_tls = TRUE;
				}
			}
		}
		fragile_exclude_and_report( reason: "- " + _split_line + " ", port: _port, proto: _proto, exclude_from_tls: exclude_from_tls, only_exclude_from_tls: only_exclude_from_tls, selfdefined: TRUE );
	}
	if(_error){
		log_message( port: 0, data: "Wrong syntax in the following line(s) of the \"Exclude specific port(s) from scan\" preference:\n\n" + _error );
	}
}
func fragile_exclude_and_report( reason, port, proto, mark_dead, exclude_from_tls, only_exclude_from_tls, selfdefined ){
	var reason, port, proto, mark_dead, exclude_from_tls, only_exclude_from_tls, selfdefined;
	var exclude_port_text, mark_dead_text, enable_text, _proto;
	exclude_port_text = "This port was excluded from the scan because of the following reason:\n\n";
	mark_dead_text = "The scan has been disabled against this host because of the following reason:\n\n";
	enable_text = "\n\nIf you want to disable this behavior please set the preference \"Exclude known fragile devices/ports from scan\" ";
	enable_text += " within the \"Global variable settings\" (OID: 1.3.6.1.4.1.25623.1.0.12288) to \"no\".";
	selfdefined_text = "configuration via the \"Exclude specific port(s) from scan\" preference of this script.";
	if(selfdefined){
		if( proto == "tcp" ){
			if(get_port_state( port )){
				if(exclude_from_tls){
					set_kb_item( name: "fragile_port/exclude_tls/" + port, value: TRUE );
				}
				if(!only_exclude_from_tls){
					service_register( port: port, proto: "fragile_port", ipproto: proto );
					replace_kb_item( name: "BannerHex/" + port, value: "aeaeaeaeae" );
					replace_kb_item( name: "Banner/" + port, value: "ignore-this-banner" );
				}
				log_message( port: port, data: exclude_port_text + reason + selfdefined_text, proto: proto );
				return;
			}
		}
		else {
			if( proto == "udp" ){
				if(get_udp_port_state( port )){
					service_register( port: port, proto: "fragile_port", ipproto: proto );
					log_message( port: port, data: exclude_port_text + reason + selfdefined_text, proto: proto );
					return;
				}
			}
			else {
				if(proto == "all"){
					for _proto in make_list( "udp",
						 "tcp" ) {
						if( _proto == "udp" ){
							if(get_udp_port_state( port )){
								service_register( port: port, proto: "fragile_port", ipproto: _proto );
								log_message( port: port, data: exclude_port_text + reason + selfdefined_text, proto: _proto );
							}
						}
						else {
							if(get_port_state( port )){
								if(exclude_from_tls){
									set_kb_item( name: "fragile_port/exclude_tls/" + port, value: TRUE );
								}
								if(!only_exclude_from_tls){
									service_register( port: port, proto: "fragile_port", ipproto: _proto );
									replace_kb_item( name: "BannerHex/" + port, value: "aeaeaeaeae" );
									replace_kb_item( name: "Banner/" + port, value: "ignore-this-banner" );
								}
								log_message( port: port, data: exclude_port_text + reason + selfdefined_text, proto: _proto );
							}
						}
					}
				}
			}
		}
		return;
	}
	if(mark_dead){
		log_message( port: 0, data: mark_dead_text + reason + enable_text );
		set_kb_item( name: "Host/dead", value: TRUE );
		exit( 0 );
	}
	if(get_port_state( port )){
		if(exclude_from_tls){
			set_kb_item( name: "fragile_port/exclude_tls/" + port, value: TRUE );
		}
		service_register( port: port, proto: "fragile_port" );
		replace_kb_item( name: "BannerHex/" + port, value: "aeaeaeaeae" );
		replace_kb_item( name: "Banner/" + port, value: "ignore-this-banner" );
		log_message( port: port, data: exclude_port_text + reason + enable_text );
		exit( 0 );
	}
}
exclude_port_definition = script_get_preference( name: "Exclude specific port(s) from scan", id: 1 );
if(strlen( exclude_port_definition ) > 0){
	check_and_apply_exclude_port_definition( exclude_port_definition: exclude_port_definition );
}
port = 9999;
if(get_port_state( port )){
	banner = telnet_get_banner( port: port );
	if(banner && ( IsMatchRegexp( banner, "Lantronix .* Device Server" ) || ( ContainsString( banner, "MAC address " ) && ContainsString( banner, "Software version " ) ) )){
		fragile_exclude_and_report( reason: "- The detected Lantronix Device is known to crash if this port is scanned.", port: 30718, exclude_from_tls: TRUE );
	}
}
port = 30718;
if(get_udp_port_state( port )){
	soc = open_sock_udp( port );
	if(soc){
		req = raw_string( 0x00, 0x00, 0x00, 0xF8 );
		send( socket: soc, data: req );
		recv = recv( socket: soc, length: 124 );
		close( soc );
		if(recv && strlen( recv ) == 124 && hexstr( substr( recv, 0, 3 ) ) == "000000f9"){
			fragile_exclude_and_report( reason: "- The detected Lantronix Device is known to crash if this port is scanned.", port: 30718, exclude_from_tls: TRUE );
		}
	}
}
port = 30718;
if(get_port_state( port )){
	soc = open_sock_tcp( port );
	if(soc){
		req = raw_string( 0x00, 0x00, 0x00, 0xF8 );
		send( socket: soc, data: req );
		recv = recv( socket: soc, length: 124 );
		close( soc );
		if(recv && strlen( recv ) == 124 && hexstr( substr( recv, 0, 3 ) ) == "000000f9"){
			fragile_exclude_and_report( reason: "- The detected Lantronix Device is known to crash if this port is scanned.", port: 30718, exclude_from_tls: TRUE );
		}
	}
}
port = 21;
if(get_port_state( port )){
	banner = ftp_get_banner( port: port );
	if(banner && ( IsMatchRegexp( banner, "220 Nucleus FTP Server \\(Version [0-9.]+\\) ready" ) )){
		fragile_exclude_and_report( reason: "- The detected device running Nucleus RTOS is known to crash if this port is scanned.", port: 21, exclude_from_tls: TRUE );
	}
}
exit( 0 );

