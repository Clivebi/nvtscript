if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16058" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2651" );
	script_bugtraq_id( 12104 );
	script_xref( name: "OSVDB", value: "12630" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "YaCy Peer-To-Peer Search Engine XSS" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to YaCy 0.32 or later." );
	script_tag( name: "summary", value: "The remote host contains a peer-to-peer search engine that is prone to
cross-site scripting attacks.

Description :

The remote host runs YaCy, a peer-to-peer distributed web search
engine and caching web proxy.

The remote version of this software is vulnerable to multiple
cross-site scripting due to a lack of sanitization of user-supplied
data.

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/385453" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
buf = http_get( item: "/index.html?urlmaskfilter=<script>foo</script>", port: port );
r = http_keepalive_send_recv( port: port, data: buf );
if(isnull( r )){
	exit( 0 );
}
if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<title>YaCy.+ Search Page</title>.*<script>foo</script>", string: r )){
	security_message( port );
	exit( 0 );
}

