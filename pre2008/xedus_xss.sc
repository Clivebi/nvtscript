if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14647" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1645" );
	script_bugtraq_id( 11071 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Xedus XSS" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_dependencies( "xedus_detect.sc", "cross_site_scripting.sc" );
	script_family( "Peer-To-Peer File Sharing" );
	script_require_ports( "Services/www", 4274 );
	script_mandatory_keys( "xedus/running" );
	script_tag( name: "solution", value: "Upgrade to the latest version and
remove .x files located in ./sampledocs folder" );
	script_tag( name: "summary", value: "The remote host runs Xedus Peer to Peer webserver.
This version is vulnerable to cross-site scripting attacks.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 4274 );
if(!get_kb_item( "xedus/" + port + "/running" )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
buf = http_get( item: "/test.x?username=<script>foo</script>", port: port );
r = http_keepalive_send_recv( port: port, data: buf );
if(isnull( r )){
	exit( 0 );
}
if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>foo</script>", string: r )){
	security_message( port );
	exit( 0 );
}
buf = http_get( item: "/TestServer.x?username=<script>foo</script>", port: port );
r = http_keepalive_send_recv( port: port, data: buf );
if(isnull( r )){
	exit( 0 );
}
if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>foo</script>", string: r )){
	security_message( port );
	exit( 0 );
}
buf = http_get( item: "/testgetrequest.x?param=<script>foo</script>", port: port );
r = http_keepalive_send_recv( port: port, data: buf );
if(isnull( r )){
	exit( 0 );
}
if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>foo</script>", string: r )){
	security_message( port );
	exit( 0 );
}
exit( 99 );

