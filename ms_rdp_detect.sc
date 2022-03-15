if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100062" );
	script_version( "2021-04-16T08:08:22+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 08:08:22 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-03-19 19:54:28 +0100 (Thu, 19 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Microsoft Remote Desktop Protocol (RDP) Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "find_service1.sc" );
	script_require_ports( "Services/unknown", "Services/ms-wbt-server", 3389 );
	script_tag( name: "summary", value: "A service supporting the Microsoft Remote Desktop Protocol (RDP)
  is running at this host." );
	script_tag( name: "insight", value: "Remote Desktop Services, formerly known as Terminal Services, is
  one of the components of Microsoft Windows (both server and client versions) that allows a user to
  access applications and data on a remote computer over a network." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
SCRIPT_DESC = "Microsoft Remote Desktop Protocol (RDP) Detection";
BANNER_TYPE = "Microsoft Remote Desktop Protocol (RDP)";
func check_xrdp( port ){
	var port, soc, req, buf, hexbuf;
	if(get_kb_item( "rdp/" + port + "/isxrdp" )){
		return TRUE;
	}
	soc = open_sock_tcp( port: port, transport: ENCAPS_IP );
	if(!soc){
		return FALSE;
	}
	req = "GET / HTTP/1.0\r\n\r\n";
	send( socket: soc, data: req );
	buf = recv( socket: soc, length: 9 );
	close( soc );
	if(isnull( buf ) || strlen( buf ) != 9){
		return FALSE;
	}
	hexbuf = hexstr( buf );
	if(hexbuf == "0300000902f0802180"){
		return TRUE;
	}
	return FALSE;
}
func check_without_cookie( port ){
	var port, soc, req, buf, hexbuf;
	soc = open_sock_tcp( port: port, transport: ENCAPS_IP );
	if(!soc){
		return FALSE;
	}
	req = raw_string( 0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00 );
	send( socket: soc, data: req );
	buf = recv( socket: soc, length: 11 );
	close( soc );
	if(isnull( buf ) || strlen( buf ) != 11){
		return FALSE;
	}
	hexbuf = hexstr( buf );
	if(IsMatchRegexp( hexbuf, "^0300000b06d00000123400$" ) || IsMatchRegexp( hexbuf, "^0300000b06d00000000000$" )){
		return TRUE;
	}
	return FALSE;
}
func check_with_cookie( port ){
	var port, soc, req, buf, hexbuf;
	soc = open_sock_tcp( port: port, transport: ENCAPS_IP );
	if(!soc){
		return FALSE;
	}
	req = raw_string( 0x03, 0x00, 0x00 );
	req += "-(";
	req += raw_string( 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00 );
	req += "Cookie: mstshash=openvas\r\n";
	req += raw_string( 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 );
	send( socket: soc, data: req );
	buf = recv( socket: soc, length: 19 );
	close( soc );
	if(isnull( buf ) || ( strlen( buf ) != 11 && strlen( buf ) != 19 )){
		return FALSE;
	}
	hexbuf = hexstr( buf );
	if(IsMatchRegexp( hexbuf, "^030000130ed000001234000200080002000000$" )){
		return make_list( "Windows, possible Windows Vista or Server 2008",
			 hexbuf );
	}
	if(IsMatchRegexp( hexbuf, "^030000130ed000001234000209080002000000$" ) || IsMatchRegexp( hexbuf, "^030000130ed000001234000201080002000000$" )){
		return make_list( "Windows, possible Windows 7 or Server 2008",
			 hexbuf );
	}
	if(IsMatchRegexp( hexbuf, "^030000130ed00000123400021f080002000000$" )){
		return make_list( "Windows, possible Windows 10 or Server 2016",
			 hexbuf );
	}
	if(IsMatchRegexp( hexbuf, "^030000130ed00000123400020f080002000000$" )){
		return make_list( "Windows, possible Windows 8, 8.1 or Server 2012",
			 hexbuf );
	}
	if(IsMatchRegexp( hexbuf, "^030000130ed000001234000300080002000000$" )){
		return make_list( "Windows, possible Windows XP 64bit SP2 or Server 2003",
			 hexbuf );
	}
	if(IsMatchRegexp( hexbuf, "^030000130ed000001234000207080002000000$" )){
		return make_list( "Windows, possible Windows 8 build 9200",
			 hexbuf );
	}
	if(IsMatchRegexp( hexbuf, "^0300000b06d00000123400$" )){
		return make_list( "Windows, possible Windows XP SP2/SP3",
			 hexbuf );
	}
	if(IsMatchRegexp( hexbuf, "^0300000b06d00000000000$" )){
		return make_list( "Unixoide",
			 hexbuf );
	}
	if(IsMatchRegexp( hexbuf, "^030000130ed000001234000201080000000000$" )){
		return make_list( "Unixoide",
			 hexbuf );
	}
	if(IsMatchRegexp( hexbuf, "^030000130ed000001234000....80002000000$" )){
		return make_list( "Unknown",
			 hexbuf );
	}
	return FALSE;
}
ports = make_list( 3389 );
unknown_ports = unknownservice_get_ports( default_port_list: make_list( 3389 ) );
if(!isnull( unknown_ports )){
	ports = make_list( ports,
		 unknown_ports );
}
known_ports = service_get_ports( default_port_list: make_list( 3389 ), proto: "ms-wbt-server" );
if(!isnull( known_ports )){
	ports = make_list( ports,
		 known_ports );
}
ports = nasl_make_list_unique( ports );
for port in ports {
	if(!get_port_state( port )){
		continue;
	}
	found = FALSE;
	isxrdp = FALSE;
	if(fp = check_with_cookie( port: port )){
		found = TRUE;
	}
	if(!found){
		if(check_without_cookie( port: port )){
			found = TRUE;
			if(check_xrdp( port: port )){
				isxrdp = TRUE;
			}
		}
	}
	if(found){
		if( fp ){
			report = fp[0] + " based on binary response fingerprinting: " + fp[1];
			if( ContainsString( fp[0], "Windows" ) ){
				os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner: report, banner_type: BANNER_TYPE, port: port, desc: SCRIPT_DESC, runs_key: "windows" );
				set_kb_item( name: "msrdp/detected", value: TRUE );
				set_kb_item( name: "rdp/detected", value: TRUE );
			}
			else {
				if( ContainsString( fp[0], "Unixoide" ) ){
					os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner: report, banner_type: BANNER_TYPE, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
					set_kb_item( name: "rdp/detected", value: TRUE );
				}
				else {
					os_register_unknown_banner( banner: report, banner_type_name: BANNER_TYPE, banner_type_short: "rdp_binary_response", port: port );
					set_kb_item( name: "msrdp/detected", value: TRUE );
					set_kb_item( name: "rdp/detected", value: TRUE );
				}
			}
		}
		else {
			if( isxrdp ){
				os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner: "Connection reset message of Xrdp", banner_type: BANNER_TYPE, port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
				set_kb_item( name: "rdp/detected", value: TRUE );
			}
			else {
				set_kb_item( name: "msrdp/detected", value: TRUE );
				set_kb_item( name: "rdp/detected", value: TRUE );
			}
		}
		service_register( port: port, proto: "ms-wbt-server" );
		log_message( port: port );
	}
}
exit( 0 );

