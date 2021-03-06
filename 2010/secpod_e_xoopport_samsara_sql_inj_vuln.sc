if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901159" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)" );
	script_cve_id( "CVE-2010-3467" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "E-Xoopport - Samsara SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41397" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61808" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15004" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1009-exploits/exoopport-sql.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL
  Injection attack and gain sensitive information." );
	script_tag( name: "affected", value: "E-Xoopport Samsara Version 3.1 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'secid' parameter to modules/sections/index.php that allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running E-Xoopport - Samsara and is prone to SQL
  injection vulnerability." );
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
for dir in nasl_make_list_unique( "/Samsara", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/modules/news/index.php", port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	version = eregmatch( pattern: ">Powered by E-Xoopport ([0-9.]+)", string: res );
	if(version[1] != NULL){
		if(version_is_less_equal( version: version[1], test_version: "3.1" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

