if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105262" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-04-22 13:23:32 +0200 (Wed, 22 Apr 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Palo Alto PAN-OS Version Detection (XML-API)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_palo_alto_webgui_detect.sc" );
	script_mandatory_keys( "palo_alto/webui/detected" );
	script_add_preference( name: "API Username: ", value: "", type: "entry" );
	script_add_preference( name: "API Password: ", value: "", type: "password" );
	script_tag( name: "summary", value: "This script performs XML-API based detection of the Palo Alto PAN-OS Version." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("url_func.inc.sc");
func exit_and_report_fail( port, reason ){
	var port, reason;
	set_kb_item( name: "palo_alto/xml-api/" + port + "/fail_reason", value: reason );
	exit( 0 );
}
if(!port = get_kb_item( "palo_alto/webui/port" )){
	exit( 0 );
}
user = script_get_preference( "API Username: " );
pass = script_get_preference( "API Password: " );
if(!user || !pass){
	if(!user && pass){
		exit_and_report_fail( port: port, reason: "API Password provided but API Username missing." );
	}
	if(user && !pass){
		exit_and_report_fail( port: port, reason: "API Username provided but API Password missing." );
	}
	exit( 0 );
}
url = "/api/?type=keygen&user=" + user + "&password=" + pass;
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(!ContainsString( buf, "success" ) || !ContainsString( buf, "<key>" )){
	if(reason = egrep( pattern: "<msg>.*</msg>", string: buf )){
		exit_and_report_fail( port: port, reason: reason );
	}
	exit_and_report_fail( port: port, reason: "Unknown error occurred while trying to generate an Access Key via '/api/?type=keygen'." );
}
match = eregmatch( pattern: "<key>([^<]+)</key>", string: buf );
if(isnull( match[1] )){
	exit_and_report_fail( port: port, reason: "Failed to fetch generated Access Key from '/api/?type=keygen'." );
}
key = urlencode( str: match[1] );
url = "/api/?type=op&cmd=%3Cshow%3E%3Csystem%3E%3Cinfo%3E%3C%2Finfo%3E%3C%2Fsystem%3E%3C%2Fshow%3E&key=" + key;
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(!ContainsString( buf, "success" ) || !ContainsString( buf, "<result>" )){
	if(reason = egrep( pattern: "<msg>.*</msg>", string: buf )){
		exit_and_report_fail( port: port, reason: reason );
	}
	exit_and_report_fail( port: port, reason: "Unknown error occurred while trying to access '/api/?type=op' via the previously generated Access Key." );
}
set_kb_item( name: "palo_alto/detected", value: TRUE );
set_kb_item( name: "palo_alto/xml-api/detected", value: TRUE );
set_kb_item( name: "palo_alto/xml-api/port", value: port );
set_kb_item( name: "palo_alto/xml-api/" + port + "/system", value: buf );
set_kb_item( name: "palo_alto/xml-api/" + port + "/concluded", value: http_report_vuln_url( port: port, url: "/api/", url_only: TRUE ) );
exit( 0 );

