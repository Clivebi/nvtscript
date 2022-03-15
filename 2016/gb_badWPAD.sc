if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105845" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-05 14:58:54 +0200 (Fri, 05 Aug 2016)" );
	script_name( "badWPAD" );
	script_tag( name: "summary", value: "The remote host is serving a Web Proxy Auto-Discovery Protocol config file.
The Web Proxy Auto-Discovery Protocol (WPAD) is a method used by clients to locate the URL of a configuration file using DHCP and/or DNS discovery methods.
Once detection and download of the configuration file is complete, it can be executed to determine the proxy for a specified URL.

There are known security issues with WPAD." );
	script_tag( name: "solution", value: "Apply the mentioned steps in the referenced advisory to mitigate the issue." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_xref( name: "URL", value: "http://www.trendmicro.co.uk/media/misc/wp-badwpad.pdf" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/wpad.dat";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "Content-Type: application/x-ns-proxy-autoconfig" ) && ContainsString( buf, "FindProxyForURL" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

