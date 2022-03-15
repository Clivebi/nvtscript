if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14782" );
	script_version( "2021-02-08T11:06:53+0000" );
	script_tag( name: "last_modification", value: "2021-02-08 11:06:53 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2402", "CVE-2004-2403" );
	script_bugtraq_id( 11214, 11215 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "YaBB 1 GOLD SP 1.3.2 Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2004-09/0227.html" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "summary", value: "Yet another Bulletin Board (YaBB) is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  - CVE-2004-2402: A Cross-Site Scripting (XSS) vulnerability. This issue is due to a failure of
  the application to properly sanitize user-supplied input.

  As a result of this vulnerability, it is possible for a remote attacker to create a malicious
  link containing script code that will be executed in the browser of an unsuspecting user when followed.

  - CVE-2004-2403: A Cross-Site Request Forgery (CSRF) vulnerability.

  - Another flaw in YaBB may allow an attacker to execute malicious administrative commands on the remote
  host by sending malformed IMG tags in posts to the remote YaBB forum and waiting for the forum
  administrator to view one of the posts." );
	script_tag( name: "affected", value: "YaBB 1 GOLD SP 1.3.2 is known to be affected. Other versions might
  be affected as well." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/yabb", "/forum", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/YaBB.pl";
	res = http_get_cache( port: port, item: url );
	if(!res || ( !ContainsString( res, "Powered by YaBB" ) && !ContainsString( res, "yabbforum.com" ) )){
		continue;
	}
	url = dir + "/YaBB.pl?board=;action=imsend;to=%22%3E%3Cscript%3Efoo%3C/script%3E";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>foo</script>", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

