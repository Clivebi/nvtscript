if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108525" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-01-03 20:47:03 +0100 (Thu, 03 Jan 2019)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Service Detection (wrapped) with nmap" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_require_ports( "Services/wrapped" );
	script_dependencies( "toolcheck.sc", "unknown_services.sc" );
	script_mandatory_keys( "Tools/Present/nmap" );
	script_tag( name: "summary", value: "This plugin performs service detection by launching nmap's
  service probe (nmap -sV) against ports that are running services marked as 'wrapped' and where
  unidentified so far.

  The actual reporting takes place in the separate NVT 'Unknown OS and Service Banner Reporting'
  OID: 1.3.6.1.4.1.25623.1.0.108441." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_timeout( 900 );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("port_service_func.inc.sc");
ver = pread( cmd: "nmap", argv: make_list( "nmap",
	 "-V" ) );
extract = eregmatch( string: ver, pattern: ".*nmap version ([0-9.]+).*", icase: TRUE );
if(isnull( extract ) || revcomp( a: extract[1], b: "4.62" ) < 0){
	exit( 0 );
}
port = get_kb_item( "Services/wrapped" );
if(!port){
	exit( 0 );
}
if(!get_port_state( port )){
	exit( 0 );
}
if(!service_is_unknown( port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port: port, transport: ENCAPS_IP );
if( !soc ) {
	exit( 0 );
}
else {
	close( soc );
}
i = 0;
ip = get_host_ip();
argv[i++] = "nmap";
if(TARGET_IS_IPV6()){
	argv[i++] = "-6";
}
timing_policy = get_kb_item( "Tools/nmap/timing_policy" );
if(IsMatchRegexp( timing_policy, "^-T[0-5]$" )){
	argv[i++] = timing_policy;
}
source_iface = get_preference( "source_iface" );
if(IsMatchRegexp( source_iface, "^[0-9a-zA-Z:_]+$" )){
	argv[i++] = "-e";
	argv[i++] = source_iface;
}
argv[i++] = "-sV";
argv[i++] = "-Pn";
argv[i++] = "-p";
argv[i++] = port;
argv[i++] = "-oG";
argv[i++] = "-";
argv[i++] = ip;
res = pread( cmd: "nmap", argv: argv );
extract = eregmatch( string: res, pattern: ".*Ports: ([0-9]+)/+open/[^/]*/[^/]*/([^/]*)/.*" );
servicesig = extract[2];
len = strlen( servicesig );
if(len > 0){
	lastchar = substr( servicesig, len - 1 );
	if(lastchar == "?"){
		servicesig = substr( servicesig, 0, len - 2 );
		guess = TRUE;
	}
}
if(strlen( servicesig ) > 0){
	set_kb_item( name: "unknown_os_or_service/available", value: TRUE );
	report = "Nmap service detection (wrapped) result for this port: " + servicesig;
	if(guess){
		command = "nmap -sV -Pn -p " + port + " " + ip;
		report += "\n\nThis is a guess. A confident identification of the service was not possible.\n\n";
		report += "Hint: If you're running a recent nmap version try to run nmap with the following command: '" + command;
		report += "' and submit a possible collected fingerprint to the nmap database.";
	}
	set_kb_item( name: "unknown_service_report/nmap/wrapped/" + port + "/report", value: report );
}
exit( 0 );

