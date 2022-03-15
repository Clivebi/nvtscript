if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11140" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "UDDI Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2005 John Lampe...j_lampe@bellsouth.net" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "embedded_web_server_detect.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The tested Web server seems to be friendly to UDDI requests.

  The server could be potentially offering web services under some other directory (we only tested
  the web root directory)" );
	exit( 0 );
}
require("uddi.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_get_is_marked_embedded( port: port )){
	exit( 0 );
}
mypath = "/";
mymessage = create_uddi_xml( ktype: "UDDI_QUERY_FBUSINESS", path: mypath, key: "", name: "e" );
soc = open_sock_tcp( port );
if( soc ){
	send( socket: soc, data: mymessage );
	getreply = http_recv( socket: soc );
	close( soc );
}
else {
	exit( 0 );
}
mystr = strstr( getreply, "serviceKey" );
if(!mystr){
	soaptest = strstr( getreply, "soap:Envelope" );
	if(soaptest){
		mywarning = NASLString( "The server seems to accept UDDI queries.  This could indicate\\n" );
		mywarning = NASLString( mywarning, " that the server is offering web services" );
		log_message( port: port, data: mywarning );
	}
	exit( 0 );
}
flag = 0;
mykey = "";
for(i = 12;flag < 1;i++){
	if( ( mystr[i] < "#" ) && ( mystr[i] > "!" ) ) {
		flag++;
	}
	else {
		mykey = NASLString( mykey, mystr[i] );
	}
}
mymessage = create_uddi_xml( ktype: "UDDI_QUERY_GSERVICE_DETAIL", path: mypath, key: mykey );
soc = open_sock_tcp( port );
if(soc){
	send( socket: soc, data: mymessage );
	getreply = http_recv( socket: soc );
}
if(egrep( pattern: mykey, string: getreply )){
	mywarning = NASLString( "The server is accepting UDDI queries.  This indicates\\n" );
	mywarning = NASLString( mywarning, " that the server is offering web services" );
	log_message( port: port, data: mywarning );
	exit( 0 );
}
if(egrep( pattern: ".*200 OK.*", string: getreply )){
	mywarning = NASLString( "The server seems to accept UDDI queries.  This could indicate\\n" );
	mywarning = NASLString( mywarning, " that the server is offering web services" );
	log_message( port: port, data: mywarning );
	exit( 0 );
}

