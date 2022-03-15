if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12288" );
	script_version( "2021-07-26T08:19:52+0000" );
	script_tag( name: "last_modification", value: "2021-07-26 08:19:52 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Global variable settings" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Settings" );
	script_add_preference( name: "Enable CGI scanning", type: "checkbox", value: "yes", id: 2 );
	script_add_preference( name: "Add historic /scripts and /cgi-bin to directories for CGI scanning", type: "checkbox", value: "no", id: 3 );
	script_add_preference( name: "Regex pattern to exclude directories from CGI scanning : ", type: "entry", value: "/(index\\.php|image|img|css|js$|js/|javascript|style|theme|icon|jquery|graphic|grafik|picture|bilder|thumbnail|media/|skins?/)", id: 4 );
	script_add_preference( name: "Use regex pattern to exclude directories from CGI scanning : ", type: "checkbox", value: "yes", id: 5 );
	script_add_preference( name: "Exclude directories containing detected known server manuals from CGI scanning", type: "checkbox", value: "yes", id: 6 );
	script_add_preference( name: "Enable generic web application scanning", type: "checkbox", value: "no", id: 7 );
	script_add_preference( name: "Disable caching of web pages during CGI scanning", type: "checkbox", value: "no", id: 18 );
	script_add_preference( name: "Traversal depth to use for directory traversal attacks during CGI scanning", type: "entry", value: "6", id: 19 );
	script_add_preference( name: "Network type", type: "radio", value: "Mixed (use RFC 1918);Private LAN;Public WAN (Internet);Public LAN", id: 8 );
	script_add_preference( name: "Report verbosity", type: "radio", value: "Normal;Quiet;Verbose", id: 9 );
	script_add_preference( name: "Log verbosity", type: "radio", value: "Normal;Quiet;Verbose;Debug", id: 10 );
	script_add_preference( name: "Debug level", type: "entry", value: "0", id: 11 );
	script_add_preference( name: "HTTP User-Agent", type: "entry", value: "", id: 12 );
	script_add_preference( name: "Strictly unauthenticated", type: "checkbox", value: "no", id: 1 );
	script_add_preference( name: "Exclude printers from scan", type: "checkbox", value: "yes", id: 13 );
	script_add_preference( name: "Exclude known fragile devices/ports from scan", type: "checkbox", value: "yes", id: 14 );
	script_add_preference( name: "Enable SSH Debug", type: "checkbox", value: "no", id: 15 );
	script_add_preference( name: "Mark host as dead if going offline (failed ICMP ping) during scan", type: "checkbox", value: "no", id: 16 );
	script_add_preference( name: "Service discovery on non-default UDP ports (slow)", type: "checkbox", value: "no", id: 17 );
	script_tag( name: "summary", value: "This plugin configures miscellaneous global variables for NASL scripts.
  It does not perform any security check but may disable or change the behaviour of others." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("network_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
opt = script_get_preference( name: "Service discovery on non-default UDP ports (slow)", id: 17 );
if(opt == "yes"){
	set_kb_item( name: "global_settings/non-default_udp_service_discovery", value: TRUE );
}
opt = script_get_preference( name: "Mark host as dead if going offline (failed ICMP ping) during scan", id: 16 );
if(opt == "yes"){
	set_kb_item( name: "global_settings/mark_host_dead_failed_icmp", value: TRUE );
}
opt = script_get_preference( name: "Enable CGI scanning", id: 2 );
if(opt == "no"){
	set_kb_item( name: "Settings/disable_cgi_scanning", value: TRUE );
}
opt = script_get_preference( name: "Exclude directories containing detected known server manuals from CGI scanning", id: 6 );
if(!opt || opt == "yes"){
	set_kb_item( name: "global_settings/cgi_dirs_exclude_servermanual", value: TRUE );
}
opt = script_get_preference( name: "Enable generic web application scanning", id: 7 );
if(opt == "no"){
	set_kb_item( name: "global_settings/disable_generic_webapp_scanning", value: TRUE );
}
opt = script_get_preference( name: "Disable caching of web pages during CGI scanning", id: 18 );
if(opt && opt == "yes"){
	set_kb_item( name: "global_settings/disable_http_kb_caching", value: TRUE );
}
opt = script_get_preference( name: "Traversal depth to use for directory traversal attacks during CGI scanning", id: 19 );
if( opt && IsMatchRegexp( opt, "^[1-9][0-9]*$" ) ) {
	depth = opt;
}
else {
	depth = "6";
}
set_kb_item( name: "global_settings/dir_traversal_depth", value: opt );
opt = script_get_preference( name: "Regex pattern to exclude directories from CGI scanning : ", id: 4 );
if( !opt ) {
	set_kb_item( name: "global_settings/cgi_dirs_exclude_pattern", value: "/(index\\.php|image|img|css|js$|js/|javascript|style|theme|icon|jquery|graphic|grafik|picture|bilder|thumbnail|media/|skins?/)" );
}
else {
	set_kb_item( name: "global_settings/cgi_dirs_exclude_pattern", value: opt );
}
opt = script_get_preference( name: "Use regex pattern to exclude directories from CGI scanning : ", id: 5 );
if(opt != "no"){
	set_kb_item( name: "global_settings/use_cgi_dirs_exclude_pattern", value: TRUE );
}
opt = script_get_preference( name: "Report verbosity", id: 9 );
if(!opt){
	opt = "Normal";
}
set_kb_item( name: "global_settings/report_verbosity", value: opt );
opt = script_get_preference( name: "Log verbosity", id: 10 );
if(!opt){
	opt = "Quiet";
}
set_kb_item( name: "global_settings/log_verbosity", value: opt );
opt = script_get_preference( name: "Debug level", id: 11 );
if(!opt){
	opt = "0";
}
set_kb_item( name: "global_settings/debug_level", value: int( opt ) );
opt = script_get_preference( name: "Network type", id: 8 );
if(!opt){
	opt = "Mixed (RFC 1918)";
}
set_kb_item( name: "global_settings/network_type", value: opt );
opt = script_get_preference( name: "HTTP User-Agent", id: 12 );
if(!opt){
	vt_strings = get_vt_strings();
	opt = http_get_user_agent( vt_string: vt_strings["default_dash"], dont_add_oid: TRUE );
}
set_kb_item( name: "global_settings/http_user_agent", value: opt );
set_kb_item( name: "http/user-agent", value: opt );
opt = script_get_preference( name: "Strictly unauthenticated", id: 1 );
if(opt == "yes"){
	set_kb_item( name: "global_settings/authenticated_scans_disabled", value: TRUE );
}
opt = script_get_preference( name: "Exclude printers from scan", id: 13 );
if(opt == "yes"){
	set_kb_item( name: "global_settings/exclude_printers", value: "yes" );
}
opt = script_get_preference( name: "Exclude known fragile devices/ports from scan", id: 14 );
if(opt == "yes"){
	set_kb_item( name: "global_settings/exclude_fragile", value: TRUE );
}
cgi_bin = cgibin();
if(cgi_bin){
	cgis = split( buffer: cgi_bin, sep: ":", keep: FALSE );
	opt = script_get_preference( name: "Add historic /scripts and /cgi-bin to directories for CGI scanning", id: 3 );
	for cgi in cgis {
		if( ( cgi == "/scripts" || cgi == "/cgi-bin" ) && ( !opt || opt == "no" ) ) {
			exclude_cgis = TRUE;
		}
		else {
			set_kb_item( name: "/user/cgis", value: cgi );
		}
	}
	if(exclude_cgis){
		set_kb_item( name: "global_settings/exclude_historic_cgi_dirs", value: TRUE );
	}
}
opt = script_get_preference( name: "Enable SSH Debug", id: 15 );
if(opt == "yes"){
	set_kb_item( name: "global_settings/ssh/debug", value: TRUE );
}
if(TARGET_IS_IPV6()){
	set_kb_item( name: "keys/TARGET_IS_IPV6", value: TRUE );
}
if(islocalhost()){
	set_kb_item( name: "keys/islocalhost", value: TRUE );
}
if(islocalnet()){
	set_kb_item( name: "keys/islocalnet", value: TRUE );
}
if(is_private_addr(get_host_ip())){
	set_kb_item( name: "keys/is_private_addr", value: TRUE );
}
if(is_public_addr(get_host_ip())){
	set_kb_item( name: "keys/is_public_addr", value: TRUE );
}

