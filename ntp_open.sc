if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10884" );
	script_version( "2021-09-24T13:56:13+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-24 13:56:13 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Network Time Protocol (NTP) / NTPd Detection (Remote)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Lodge" );
	script_family( "Product detection" );
	script_require_udp_ports( "Services/udp/ntp", 123 );
	script_tag( name: "summary", value: "Detection of services supporting the Network Time Protocol
  (NTP). In addition to the protocol itself the existence of the ntpd (NTPd) daemon is detected
  as well." );
	script_tag( name: "insight", value: "It is possible to determine a lot of information about the
  remote host by querying the NTP variables - these include OS descriptor, and time settings." );
	script_tag( name: "solution", value: "Quickfix: Restrict default access to ignore all info packets." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
func ntp_read_list( port ){
	var port;
	var data, soc, r, no_bin, p;
	data = raw_string( 0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
	soc = open_sock_udp( port );
	if(!soc){
		return NULL;
	}
	send( socket: soc, data: data );
	r = recv( socket: soc, length: 4096 );
	close( soc );
	if(!r){
		return NULL;
	}
	no_bin = bin2string( ddata: r, noprint_replacement: "" );
	if(egrep( string: no_bin, pattern: "(associd|status|version|processor|system|leap)=.+", icase: TRUE )){
		set_kb_item( name: "ntp/mode6/response/received", value: TRUE );
		set_kb_item( name: "ntp/mode6/response/" + port + "/received", value: TRUE );
		set_kb_item( name: "ntp/mode6/response/" + port + "/sent_data_len", value: strlen( data ) );
		set_kb_item( name: "ntp/mode6/response/" + port + "/recv_data_len", value: strlen( r ) );
	}
	p = strstr( r, "version=" );
	if(!p){
		p = strstr( r, "processor=" );
	}
	if(!p){
		p = strstr( r, "system=" );
	}
	p = ereg_replace( string: p, pattern: raw_string( 0x22 ), replace: "'" );
	if(p){
		return ( p );
	}
	return NULL;
}
func ntp_installed( port ){
	var port;
	var data, soc, r;
	data = raw_string( 0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA, 0x00, 0x00 );
	soc = open_sock_udp( port );
	if(!soc){
		return NULL;
	}
	send( socket: soc, data: data );
	r = recv( socket: soc, length: 4096 );
	close( soc );
	if(strlen( r ) > 10){
		return ( r );
	}
	return NULL;
}
port = service_get_port( default: 123, ipproto: "udp", proto: "ntp" );
r = ntp_installed( port: port );
if(r){
	set_kb_item( name: "ntp/remote/detected", value: TRUE );
	set_kb_item( name: "ntp/detected", value: TRUE );
	service_register( port: port, proto: "ntp", ipproto: "udp" );
	list = ntp_read_list( port: port );
	if( !list ){
		log_message( port: port, protocol: "udp" );
	}
	else {
		if(ContainsString( list, "system=" )){
			system_line = egrep( pattern: "system=", string: list );
			os = ereg_replace( string: system_line, pattern: ".*system='?([^',]+)[',].*", replace: "\\1" );
			set_kb_item( name: "ntp/system_banner/available", value: TRUE );
			set_kb_item( name: "ntp/" + port + "/system_banner", value: os );
		}
		if(ContainsString( list, "processor=" )){
			processor_line = egrep( pattern: "processor=", string: list );
			processor = ereg_replace( string: processor_line, pattern: ".*processor='?([^',]+)[',].*", replace: "\\1" );
			set_kb_item( name: "Host/processor/ntp", value: processor );
			set_kb_item( name: "ntp/processor_banner/available", value: TRUE );
			set_kb_item( name: "ntp/" + port + "/processor_banner", value: processor );
			register_host_detail( name: "cpuinfo", value: processor, desc: "NTP(d) Server Detection" );
		}
		if(ContainsString( list, "version=" )){
			version_line = eregmatch( pattern: "version='([^']+)',", string: list );
			if(!isnull( version_line[1] )){
				set_kb_item( name: "ntp/version_banner/available", value: TRUE );
				set_kb_item( name: "ntp/" + port + "/version_banner", value: version_line[1] );
			}
		}
		if(ContainsString( list, "ntpd" )){
			set_kb_item( name: "ntpd/remote/detected", value: TRUE );
			set_kb_item( name: "ntpd/detected", value: TRUE );
			install = port + "/udp";
			version = "unknown";
			CPE = "cpe:/a:ntp:ntp";
			vers = eregmatch( pattern: ".*ntpd ([0-9.]+)([a-z][0-9]*)?-?((RC|beta)[0-9]+)?", string: list );
			if(!isnull( vers[1] )){
				if( IsMatchRegexp( vers[2], "[a-z][0-9]+" ) && IsMatchRegexp( vers[3], "(RC|beta)" ) ){
					version = vers[1] + vers[2] + " " + vers[3];
					CPE += ":" + vers[1] + ":" + vers[2] + "-" + vers[3];
				}
				else {
					if( IsMatchRegexp( vers[2], "[a-z][0-9]*" ) ){
						version = vers[1] + vers[2];
						CPE += ":" + vers[1] + ":" + vers[2];
					}
					else {
						version = vers[1];
						CPE += ":" + vers[1];
					}
				}
			}
			if(version && version != "unknown"){
				CPE = tolower( CPE );
				set_kb_item( name: "ntpd/version/detected", value: TRUE );
				set_kb_item( name: "ntpd/version", value: version );
				set_kb_item( name: "ntpd/" + port + "/version", value: version );
				set_kb_item( name: "ntpd/remote/version/detected", value: TRUE );
				set_kb_item( name: "ntpd/remote/version", value: version );
				set_kb_item( name: "ntpd/remote/" + port + "/version", value: version );
			}
			register_product( cpe: CPE, location: install, port: port, service: "ntp", proto: "udp" );
			report = build_detection_report( app: "NTPd", version: version, install: install, cpe: CPE, concluded: vers[0] );
		}
		if(report){
			report += "\n\n";
		}
		report += "It was possible to gather the following information from the remote NTP host:\n\n" + chomp( list );
		log_message( port: port, proto: "udp", data: report );
		exit( 0 );
	}
}
exit( 0 );

