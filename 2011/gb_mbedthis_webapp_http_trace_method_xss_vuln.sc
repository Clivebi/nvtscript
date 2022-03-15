if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802350" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2007-3008" );
	script_bugtraq_id( 24456 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-12-02 14:47:36 +0530 (Fri, 02 Dec 2011)" );
	script_name( "Mbedthis AppWeb HTTP TRACE Method Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/25636" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/867593" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/34854" );
	script_xref( name: "URL", value: "http://www.appwebserver.org/forum/viewtopic.php?t=996" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 7777 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to gain sensitive information
  or inject arbitrary web script or HTML. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Mbedthis AppWeb versions prior to 2.2.2" );
	script_tag( name: "insight", value: "The flaw is due to improper handling of HTTP requests using the
  'TRACE' method, which allows attackers to inject arbitrary HTML via
  crafted HTTP TRACE request." );
	script_tag( name: "solution", value: "Disable TRACE method or upgrade to Mbedthis AppWeb 2.2.2 or later" );
	script_tag( name: "summary", value: "The host is running Mbedthis AppWeb Server and is prone to cross
  site scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 7777 );
host = http_host_name( port: port );
res = http_get_cache( item: "/doc/product/index.html", port: port );
if(ContainsString( res, "<title>Mbedthis AppWeb" ) || ContainsString( res, "<title>Mbedthis Appweb" )){
	req = NASLString( "TRACE /doc/product/index.html HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n\\r\\n" );
	res = http_send_recv( port: port, data: req );
	if(egrep( pattern: "^HTTP/1\\.[01] 200", string: res ) && ContainsString( res, "TRACE" ) && !ContainsString( res, "UnknownMethod 400 Bad Request" )){
		security_message( port: port );
	}
}

