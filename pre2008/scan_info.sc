if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19506" );
	script_version( "2021-03-23T06:51:29+0000" );
	script_tag( name: "last_modification", value: "2021-03-23 06:51:29 +0000 (Tue, 23 Mar 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Information about the scan" );
	script_category( ACT_END );
	script_copyright( "Copyright (C) 2004 Tenable Network Security" );
	script_family( "General" );
	script_add_preference( name: "Be silent", type: "checkbox", value: "yes", id: 1 );
	script_tag( name: "summary", value: "This script displays, for each tested host, information about the scan itself:

  - The version of the NVT feed

  - The type of NVT feed (Direct, Registered or GPL)

  - The version of the Scanner Engine

  - The port scanner(s) used

  - The port range scanned

  - The date of the scan

  - The duration of the scan

  - The number of hosts scanned in parallel

  - The number of checks done in parallel" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("plugin_feed_info.inc.sc");
require("global_settings.inc.sc");
be_silent = script_get_preference( name: "Be silent", id: 1 );
if(ContainsString( be_silent, "yes" )){
	exit( 0 );
}
version = OPENVAS_VERSION;
if(isnull( version )){
	version = "Unknown";
}
report = "Information about this scan : \n\n";
report += "Scanner version : " + version + "\n";
if(PLUGIN_SET){
	report += "NVT feed version : " + PLUGIN_SET + "\n";
	report += "Type of NVT feed : " + PLUGIN_FEED + "\n";
}
report += "Scanner IP : " + this_host() + "\n";
list = get_kb_list( "Host/scanners/*" );
if(!isnull( list )){
	for item in keys( list ) {
		item -= "Host/scanners/";
		scanners += item + " ";
	}
	report += "Port scanner(s) : " + scanners + "\n";
}
range = get_preference( "port_range" );
if(!range){
	range = "(?)";
}
report += "Port range : " + range + "\n";
report += "Report Verbosity : ";
report += report_verbosity + "\n";
report += "Safe checks : ";
if( safe_checks() ) {
	report += "yes\n";
}
else {
	report += "no\n";
}
report += "Max hosts : " + get_preference( "max_hosts" ) + "\n";
report += "Max checks : " + get_preference( "max_checks" ) + "\n";
start = get_kb_item( "/tmp/start_time" );
if(start){
	time = localtime( start );
	if( time["min"] < 10 ) {
		zero = "0";
	}
	else {
		zero = NULL;
	}
	report += "Scan Start Date : " + time["year"] + "/" + time["mon"] + "/" + time["mday"] + " " + time["hour"] + ":" + zero + time["min"] + "\n";
}
if( !start ) {
	scan_duration = "unknown (host_alive_detection.nasl not launched?)";
}
else {
	scan_duration = NASLString( unixtime() - start, " sec" );
}
report += "Scan duration : " + scan_duration;
log_message( port: 0, data: report );
exit( 0 );

