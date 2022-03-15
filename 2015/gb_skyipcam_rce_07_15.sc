if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105318" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-2280" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_name( "AirLink101 SkyIPCam1620W OS Command Injection" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/advisories/airlink101-skyipcam1620w-os-command-injection" );
	script_tag( name: "vuldetect", value: "Try to access snwrite.cgi" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "summary", value: "The SkyIPCam1620W Wireless N MPEG4 3GPP Network Camera is vulnerable
  to an OS Command Injection Vulnerability in the snwrite.cgi binary." );
	script_tag( name: "affected", value: "AirLink101 SkyIPCam1620W Wireless N MPEG4 3GPP Network Camera with
  firmware FW_AIC1620W_1.1.0-12_20120709_r1192.pck (Aug. 2012). Other devices based on the same firmware
  are probably affected too." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-07-09 11:01:55 +0200 (Thu, 09 Jul 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "SkyIPCam/banner" );
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
if(!ContainsString( banner, "Basic realm=\"SkyIPCam\"" )){
	exit( 0 );
}
auth = base64( str: "productmaker:ftvsbannedcode" );
url = "/maker/snwrite.cgi";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( buf, "^HTTP/1\\.[01] 401" )){
	exit( 0 );
}
req = http_get( item: url, port: port );
req = ereg_replace( string: req, pattern: "\r\n\r\n", replace: "\r\nAuthorization: Basic " + auth + "\r\n\r\n" );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "Network Camera" ) && ContainsString( buf, "id=\"mac\"" ) && IsMatchRegexp( buf, "value=\"[0-9A-F:]+\"" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

