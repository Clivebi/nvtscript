if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800145" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5214", "CVE-2008-5215" );
	script_bugtraq_id( 29156 );
	script_name( "ClanLite SQL Injection and Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/5595" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/42331" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful attack could lead to execution of arbitrary scripting code or
  SQL commands in the context of an affected application, which allows an
  attacker to steal cookie-based authentication credentials or access and modify data." );
	script_tag( name: "affected", value: "ClanLite Version 2.2006.05.20 and prior." );
	script_tag( name: "insight", value: "The flaws are due to error in service/calendrier.php and
  service/profil.php which are not properly sanitized before being used." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running ClanLite, and is prone to SQL Injection and
  Cross-Site Scripting Vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/clanlite", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir + "/service/index_pri.php" ), port: port );
	if(!rcvRes){
		continue;
	}
	if(ContainsString( rcvRes, "<title>ClanLite" )){
		if(safe_checks()){
			clVer = eregmatch( pattern: "ClanLite<.+ V([0-9.]+)", string: rcvRes );
			if(clVer[1] != NULL){
				if(version_is_less_equal( version: clVer[1], test_version: "2.2006.05.20" )){
					security_message( port: port );
				}
			}
			exit( 0 );
		}
		url = NASLString( dir + "/service/calendrier.php?mois=6&annee='><script>alert(document.cookie)</script>" );
		sndReq = http_get( item: url, port: port );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq, bodyonly: TRUE );
		if(!rcvRes){
			continue;
		}
		if(ContainsString( rcvRes, "<script>alert(document.cookie)</script>" )){
			security_message( port: port );
		}
		exit( 0 );
	}
}
exit( 99 );

