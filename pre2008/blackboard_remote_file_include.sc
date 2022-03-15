if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15450" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1582" );
	script_bugtraq_id( 11336 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "BlackBoard Internet Newsboard System remote file include flaw" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the newest version of this software." );
	script_tag( name: "summary", value: "The remote version of BlackBoard Internet Newsboard System is vulnerable
  to a remote file include flaw due to a lack of sanitization of user-supplied data." );
	script_tag( name: "impact", value: "Successful exploitation of this issue may allow an attacker to execute
  malicious script code on a vulnerable server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
r = http_get_cache( item: "/forum.php", port: port );
if(!r){
	exit( 0 );
}
if(egrep( pattern: "<title>BlackBoard Internet Newsboard System</title>.*BlackBoard.*(0\\.|1\\.([0-4]|5[^.]|5\\.1[^-]|5\\.1-[a-g]))", string: r )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

