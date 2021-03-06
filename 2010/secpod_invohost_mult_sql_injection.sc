if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901112" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)" );
	script_cve_id( "CVE-2010-1336" );
	script_bugtraq_id( 38962 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "INVOhost Multiple SQL injection vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39095" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38962" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/11874" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "INVOhost version 3.4 and prior." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied input
  via the 'id' and 'newlanguage' parameters in 'site.php', 'search' parameter in
  'manuals.php', and unspecified vectors in 'faq.php' that allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running INVOhost and is prone to multiple SQL
  injection vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
for dir in nasl_make_list_unique( "/", "/invohost", "/INVOHOST", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/site.php", port: port );
	if(ContainsString( res, "Powered by INVOHOST" )){
		ver = eregmatch( pattern: "version ([0-9.]+)", string: res );
		if(ver[1] != NULL){
			if(version_is_less_equal( version: ver[1], test_version: "3.4" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

