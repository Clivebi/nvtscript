if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801396" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)" );
	script_cve_id( "CVE-2010-2933" );
	script_bugtraq_id( 42023 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "AV Arcade 'ava_code' Cookie Parameter SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/60799" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14494/" );
	script_tag( name: "insight", value: "The flaws are due to an improper validation of authentication
  cookies in the 'index.php' script, when processing the 'ava_code' cookie parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running AV Arcade and is prone SQL injection
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to bypass security
  restrictions and gain unauthorized administrative access to the vulnerable application." );
	script_tag( name: "affected", value: "AV Scripts AV Arcade version 3.0" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/avarcade", "/avarcade/upload", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, ">AV Arcade" ) && ContainsString( res, ">AV Scripts</" )){
		req = http_get( item: dir + "/admin/stats.php", port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ">AV Arcade" )){
			version = eregmatch( pattern: "> ([0-9.]+)", string: res );
			if(version[1]){
				if(version_is_equal( version: version[1], test_version: "3.0" )){
					report = report_fixed_ver( installed_version: version[1], fixed_version: "WillNotFix" );
					security_message( port: port, data: report );
					exit( 0 );
				}
			}
		}
	}
}
exit( 99 );

