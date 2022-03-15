if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108021" );
	script_version( "2021-08-12T13:22:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 13:22:20 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-11-21 12:08:04 +0100 (Mon, 21 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap OS Identification (NASL wrapper)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "secpod_open_tcp_ports.sc", "toolcheck.sc", "os_fingerprint.sc" );
	script_mandatory_keys( "TCP/PORTS", "Tools/Present/nmap" );
	script_xref( name: "URL", value: "https://nmap.org/book/man-os-detection.html" );
	script_xref( name: "URL", value: "https://nmap.org/book/osdetect.html" );
	script_add_preference( name: "Guess OS more aggressively (safe checks off only)", type: "checkbox", value: "no", id: 1 );
	script_add_preference( name: "Guess OS more aggressively even if safe checks are set", type: "checkbox", value: "no", id: 2 );
	script_add_preference( name: "Run routine", type: "checkbox", value: "yes", id: 3 );
	script_tag( name: "summary", value: "This plugin runs nmap to identify the remote Operating System.

  NOTE: This routine is only started as a last fallback if other more reliable OS detection methods failed.

  This routine also has a few additional drawbacks:

  - Depending on the exposed services on the target it might take a considerable amount of time to complete

  - It needs to conntect to TCP ports which might be not within the configured port list of this target

  - It might interfere with other service detection methods of the scanner

  Due to this it is possible to disable this routine via the script preferences." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
run_routine = script_get_preference( name: "Run routine", id: 3 );
if(!run_routine){
	run_routine = "yes";
}
if(run_routine == "no"){
	exit( 0 );
}
reports = get_kb_list( "os_detection_report/reports/*" );
if( reports && max_index( keys( reports ) ) == 1 ){
	if(!in_array( search: "1.3.6.1.4.1.25623.1.0.102002", array: reports, part_match: TRUE )){
		exit( 0 );
	}
	confidence = get_kb_list( "Host/OS/ICMP/Confidence" );
	if(confidence && max_index( keys( confidence ) ) == 1){
		if(int( confidence["Host/OS/ICMP/Confidence"] ) >= 95){
			exit( 0 );
		}
	}
}
else {
	if(reports && max_index( keys( reports ) ) > 1){
		exit( 0 );
	}
}
openPorts = tcp_get_all_ports();
if(!openPorts || max_index( openPorts ) == 0){
	exit( 0 );
}
tmpfile = NULL;
func on_exit(  ){
	if(tmpfile && file_stat( tmpfile )){
		unlink( tmpfile );
	}
}
safe_opt = script_get_preference( name: "Guess OS more aggressively even if safe checks are set", id: 2 );
if( safe_opt && ContainsString( safe_opt, "yes" ) ) {
	safe = 0;
}
else {
	safe = safe_checks();
}
ip = get_host_ip();
i = 0;
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
argv[i++] = "-n";
argv[i++] = "-Pn";
argv[i++] = "-sV";
argv[i++] = "-oN";
tmpdir = get_tmp_dir();
if(tmpdir && strlen( tmpdir )){
	tmpfile = strcat( tmpdir, "nmap-", ip, "-", rand() );
	fwrite( data: " ", file: tmpfile );
}
if( tmpfile && file_stat( tmpfile ) ) {
	argv[i++] = tmpfile;
}
else {
	argv[i++] = "-";
}
argv[i++] = "-O";
argv[i++] = "--osscan-limit";
if(!safe){
	p = script_get_preference( name: "Guess OS more aggressively (safe checks off only)", id: 1 );
	if(ContainsString( p, "yes" )){
		argv[i++] = "--osscan-guess";
	}
}
argv[i++] = "-p";
portList = NULL;
for port in openPorts {
	if(port == "27960"){
		continue;
	}
	if(port_is_marked_fragile( port: port )){
		continue;
	}
	if( isnull( portList ) ) {
		portList = port;
	}
	else {
		portList += "," + port;
	}
}
for port in make_list( "21",
	 "22",
	 "25",
	 "80",
	 "135",
	 "139",
	 "443",
	 "445" ) {
	if(port_is_marked_fragile( port: port )){
		continue;
	}
	if(!in_array( search: port, array: openPorts )){
		if( isnull( portList ) ) {
			portList = port;
		}
		else {
			portList += "," + port;
		}
	}
}
numClosedPorts = 3;
for(j = 1;j <= numClosedPorts;j++){
	closedPort = rand_str( length: ( 4 ), charset: "0123456789" );
	for(;ContainsString( portList, j + closedPort ) || port_is_marked_fragile( port: j + closedPort );){
		closedPort = rand_str( length: ( 4 ), charset: "0123456789" );
	}
	portList += "," + j + closedPort;
}
argv[i++] = portList;
argv[i++] = ip;
res = pread( cmd: "nmap", argv: argv, cd: TRUE );
if(ContainsString( res, "TCP/IP fingerprinting (for OS scan) requires root privileges." )){
	log_message( port: 0, data: "ERROR: TCP/IP fingerprinting (for OS scan) requires root privileges but scanner is running under an unprivileged user. Start scanner as root to get this scan working." );
	exit( 0 );
}
if(tmpfile && file_stat( tmpfile )){
	res = fread( tmpfile );
}
if(!res){
	exit( 0 );
}
if(ContainsString( res, "JUST GUESSING" ) || ContainsString( res, "test conditions non-ideal" ) || ContainsString( res, "No exact OS matches for host" ) || ContainsString( res, "No OS matches for host" )){
	pattern = "([0-9]+)( services? unrecognized despite returning data).*\\);";
	if(eregmatch( pattern: pattern, string: res )){
		res = ereg_replace( string: res, pattern: pattern, replace: "*** unknown fingerprints replaced ***" );
	}
	os_register_unknown_banner( banner: res, banner_type_name: "Nmap TCP/IP fingerprinting", banner_type_short: "nmap_os" );
	exit( 0 );
}
osTxt = eregmatch( string: res, pattern: "OS( details)?:\\s*([^\\n;]+)", icase: FALSE );
if(osTxt[2]){
	if( ContainsString( tolower( osTxt[2] ), "windows" ) ) {
		runs_key = "windows";
	}
	else {
		runs_key = "unixoide";
	}
	os_register_and_report( os: osTxt[2], banner_type: "Nmap TCP/IP fingerprinting", banner: "\n" + osTxt[0], desc: "Nmap OS Identification (NASL wrapper)", runs_key: runs_key );
}
exit( 0 );

