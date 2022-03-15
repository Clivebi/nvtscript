if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103306" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-10-20 15:15:44 +0200 (Thu, 20 Oct 2011)" );
	script_bugtraq_id( 50286 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Boonex Dolphin 'xml/get_list.php' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50286" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520146" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/lab/PT-2011-14" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Boonex Dolphin is prone to an SQL-injection vulnerability because the
  application fails to properly sanitize user-supplied input before using it in an SQL query." );
	script_tag( name: "impact", value: "A successful exploit may allow an attacker to compromise the
  application, access or modify data, or exploit vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Boonex Dolphin 6.1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/dolphin", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( buf, "dolRSSFeed();" ) && !ContainsString( buf, "BxDolVoting.js" ) && !ContainsString( buf, "dolTopMenu.js" ) )){
		continue;
	}
	url = NASLString( dir, "/xml/get_list.php?dataType=ApplyChanges&iNumb=1&iIDcat=%27" );
	if(http_vuln_check( port: port, url: url, pattern: "You have an error in your SQL syntax" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

