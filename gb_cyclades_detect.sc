if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105068" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-08-19 11:37:55 +0200 (Tue, 19 Aug 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cyclades Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts
  to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if( http_can_host_asp( port: port ) && http_can_host_php( port: port ) ){
	urls = make_list( "/home.asp",
		 "/logon.php?redirect=index.php&nouser=1" );
}
else {
	if( http_can_host_asp( port: port ) ){
		urls = make_list( "/home.asp" );
	}
	else {
		if( http_can_host_php( port: port ) ){
			urls = make_list( "/logon.php?redirect=index.php&nouser=1" );
		}
		else {
			exit( 0 );
		}
	}
}
for url in urls {
	buf = http_get_cache( item: url, port: port );
	if(!ContainsString( buf, "Welcome to the Cyclades" )){
		continue;
	}
	set_kb_item( name: "cyclades/installed", value: TRUE );
	CL = TRUE;
	install = url;
	if(ContainsString( buf, "class=\"is\"" )){
		ts = TRUE;
	}
	lines = split( buffer: buf, keep: FALSE );
	x = 0;
	f = 0;
	for line in lines {
		x++;
		if( ContainsString( line, "class=\"is\"" ) ){
			f++;
			match = eregmatch( pattern: "<center>([^<]+)", string: line );
			if(!isnull( match[1] )){
				info[f] = match[1];
			}
		}
		else {
			if(ContainsString( line, "color=\"#003366\"" ) && !ts){
				f++;
				match = eregmatch( pattern: "([^ <]+)", string: lines[x] );
				if(!isnull( match[1] )){
					info[f] = match[1];
				}
			}
		}
	}
}
if(!CL || !info){
	exit( 0 );
}
model = "unknown";
vers = "unknown";
if(!isnull( info[1] )){
	model = info[1];
}
if(!isnull( info[2] )){
	host = info[2];
}
if(!isnull( info[3] )){
	version = eregmatch( pattern: "V_([^ ]+)", string: info[3] );
	if(!isnull( version[1] )){
		vers = version[1];
	}
}
set_kb_item( name: "cyclades/model", value: model );
set_kb_item( name: "cyclades/fw_version", value: vers );
set_kb_item( name: "cyclades/hostname", value: host );
cpe = "cpe:/o:cyclades:" + tolower( model ) + ":" + tolower( vers );
os_register_and_report( os: "Cyclades " + model, cpe: cpe, banner_type: "HTTP banner", desc: "Cyclades Detection", runs_key: "unixoide" );
data = "The remote host is a Cyclades-" + model + ".\nFirmware Version: " + vers + "\n";
if(host){
	data += "Hostname: " + host;
}
log_message( data: data, port: port );
exit( 0 );

