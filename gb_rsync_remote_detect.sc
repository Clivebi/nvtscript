if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108731" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-03-24 13:59:25 +0000 (Tue, 24 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "rsync Detection (Remote)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "find_service1.sc", "find_service2.sc" );
	script_require_ports( "Services/rsync", 873 );
	script_tag( name: "summary", value: "A service supporting the rsync protocol is running at this host." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("rsync_func.inc.sc");
require("port_service_func.inc.sc");
port = rsync_get_port( default: 873 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
res = recv_line( socket: soc, length: 1024 );
if(!res || ( !IsMatchRegexp( res, "^@RSYNCD: [0-9.]+" ) && !IsMatchRegexp( res, "^You are not welcome to use rsync from " ) && !IsMatchRegexp( res, "^rsync: (link_stat |error |.+unknown option)" ) && !IsMatchRegexp( res, "rsync error: (syntax or usage error|some files/attrs were not transferred) " ) && !IsMatchRegexp( res, "rsync\\s+version\\s+.+\\s+protocol version " ) )){
	close( soc );
	exit( 0 );
}
set_kb_item( name: "rsync/detected", value: TRUE );
set_kb_item( name: "rsync/remote/detected", value: TRUE );
service_register( port: port, ipproto: "tcp", proto: "rsync", message: "A service supporting the rsync protocol is running at this port." );
protocol = eregmatch( string: res, pattern: "(^@RSYNCD:|\\s+protocol version) ([0-9.]+)", icase: FALSE );
if(protocol[2]){
	report = "Detected RSYNCD protocol version: " + protocol[2];
	set_kb_item( name: "rsync/protocol_banner/" + port, value: protocol[0] );
	set_kb_item( name: "rsync/protocol_banner/available", value: TRUE );
}
if(IsMatchRegexp( res, "^You are not welcome to use rsync from " )){
	if(report){
		report += "\n\n";
	}
	report += "The rsync service is not allowing connections from this host.";
}
motd = "";
for(;TRUE;){
	buf = recv_line( socket: soc, length: 8096 );
	if(!buf || strstr( buf, "@ERROR" )){
		break;
	}
	motd += buf;
}
close( soc );
if(IsMatchRegexp( motd, "rsync: (link_stat |error |.+unknown option)" ) || ContainsString( motd, "rsync error: " ) || IsMatchRegexp( res, "rsync: (link_stat |error |.+unknown option)" ) || ContainsString( res, "rsync error: " )){
	motd_has_error = TRUE;
	if(report){
		report += "\n\n";
	}
	if(!ContainsString( res, "@RSYNCD:" )){
		motd = res + motd;
	}
	report += "The rsync service is in a non-working state and reports the following error:\n\n" + chomp( motd );
}
if(motd && !motd_has_error){
	motd = chomp( motd );
	if(report){
		report += "\n\n";
	}
	report += "Message of the Day reported by the service:\n\n" + motd;
	set_kb_item( name: "rsync/motd/" + port, value: motd );
	set_kb_item( name: "rsync/motd/available", value: TRUE );
}
vers = eregmatch( string: res, pattern: "rsync\\s+version ([0-9.]+)\\s+protocol version [0-9.]+", icase: FALSE );
if(vers[1] && ContainsString( motd, "samba.org" )){
	cpe = "cpe:/a:samba:rsync:" + vers[1];
	install = port + "/tcp";
	register_product( cpe: cpe, location: install, port: port, service: "rsync" );
	report += "\n\n" + build_detection_report( app: "rsync", version: vers[1], install: install, cpe: cpe, concluded: vers[0] );
}
log_message( port: port, data: report );
exit( 0 );

