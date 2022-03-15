if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108245" );
	script_version( "2021-01-26T13:20:44+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-26 13:20:44 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2017-10-09 08:07:41 +0200 (Mon, 09 Oct 2017)" );
	script_name( "SSL/TLS: HTTP Public Key Pinning (HPKP) Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_tls_version_get.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "ssl_tls/port" );
	script_xref( name: "URL", value: "https://owasp.org/www-project-secure-headers/" );
	script_xref( name: "URL", value: "https://owasp.org/www-project-secure-headers/#public-key-pinning-extension-for-http-hpkp" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc7469" );
	script_xref( name: "URL", value: "https://securityheaders.io/" );
	script_tag( name: "summary", value: "Checks if the remote web server has HPKP enabled.

  Note: Most major browsers have dropped / deprecated support for this header in 2020." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443, ignore_cgi_disabled: TRUE );
if(get_port_transport( port ) < ENCAPS_SSLv23){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!banner || !IsMatchRegexp( banner, "^HTTP/1\\.[01] [0-9]{3}" )){
	exit( 0 );
}
if(!pkp = egrep( pattern: "^Public-Key-Pins\\s*:", string: banner, icase: TRUE )){
	if(!IsMatchRegexp( banner, "^HTTP/1\\.[01] 304" )){
		set_kb_item( name: "hpkp/missing", value: TRUE );
		set_kb_item( name: "hpkp/missing/port", value: port );
	}
	exit( 0 );
}
pkp = chomp( pkp );
pkp_lo = tolower( pkp );
if(!ContainsString( pkp_lo, "max-age=" )){
	set_kb_item( name: "hpkp/missing", value: TRUE );
	set_kb_item( name: "hpkp/missing/port", value: port );
	set_kb_item( name: "hpkp/max_age/missing/" + port, value: TRUE );
	set_kb_item( name: "hpkp/" + port + "/banner", value: pkp );
	exit( 0 );
}
if(ContainsString( pkp_lo, "max-age=0" )){
	set_kb_item( name: "hpkp/missing", value: TRUE );
	set_kb_item( name: "hpkp/missing/port", value: port );
	set_kb_item( name: "hpkp/max_age/zero/" + port, value: TRUE );
	set_kb_item( name: "hpkp/" + port + "/banner", value: pkp );
	exit( 0 );
}
if(!ContainsString( pkp_lo, "pin-sha256=" )){
	set_kb_item( name: "hpkp/missing", value: TRUE );
	set_kb_item( name: "hpkp/missing/port", value: port );
	set_kb_item( name: "hpkp/pin/missing/" + port, value: TRUE );
	set_kb_item( name: "hpkp/" + port + "/banner", value: pkp );
	exit( 0 );
}
set_kb_item( name: "hpkp/available", value: TRUE );
set_kb_item( name: "hpkp/available/port", value: port );
set_kb_item( name: "hpkp/" + port + "/banner", value: pkp );
if(!ContainsString( pkp_lo, "includesubdomains" )){
	set_kb_item( name: "hpkp/includeSubDomains/missing", value: TRUE );
	set_kb_item( name: "hpkp/includeSubDomains/missing/port", value: port );
}
ma = eregmatch( pattern: "max-age=([0-9]+)", string: pkp, icase: TRUE );
if(!isnull( ma[1] )){
	set_kb_item( name: "hpkp/max_age/" + port, value: ma[1] );
}
log_message( port: port, data: "The remote web server is sending the \"HTTP Public Key Pinning\" header.\n\nHPKP-Header:\n\n" + pkp );
exit( 0 );

