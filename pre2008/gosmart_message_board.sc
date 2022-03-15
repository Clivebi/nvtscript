if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15451" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1588", "CVE-2004-1589" );
	script_bugtraq_id( 11361 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "GoSmart message board multiple flaws" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the newest version of this software" );
	script_tag( name: "summary", value: "The remote host is running GoSmart message board, a bulletin board
manager written in ASP.


The remote version of this software contains multiple flaws, due o
to a failure of the application to properly sanitize user-supplied input.

It is also affected by a cross-site scripting vulnerability.
As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed
in the browser of an unsuspecting user when followed.

Furthermore, this version is vulnerable to SQL injection flaws that
let an attacker inject arbitrary SQL commands." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/messageboard", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = NASLString( dir, "/Forum.asp?QuestionNumber=1&Find=1&Category=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E%3C%22" );
	req = http_get( item: req, port: port );
	r = http_keepalive_send_recv( port: port, data: req );
	if(isnull( r )){
		continue;
	}
	if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>foo</script>", string: r )){
		security_message( port );
		exit( 0 );
	}
}

