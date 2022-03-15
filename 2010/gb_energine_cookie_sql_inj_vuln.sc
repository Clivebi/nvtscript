if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801643" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)" );
	script_cve_id( "CVE-2010-4185" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Energine 'NRGNSID' Cookie SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41973" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15327" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/sql_injection_in_energine.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "Energine Version 2.3.8 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'NRGNSID' cookie to 'index.php', which allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Energine and is prone to SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/energine", "/energine/htdocs", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/", port: port );
	if(egrep( pattern: "Powered by.*>Energine<", string: res )){
		req = NASLString( chomp( req ), "\\r\\nCookie:  NRGNSID='\\r\\n\\r\\n" );
		res = http_keepalive_send_recv( port: port, data: req );
		if(( ContainsString( res, "ERR_DATABASE_ERROR" ) ) && egrep( pattern: "DELETE.*FROM.*WHERE", string: res )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

