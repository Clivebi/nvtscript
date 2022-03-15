if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801238" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)" );
	script_bugtraq_id( 41700 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "ViArt CMS 'admin_articles.php' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40621" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/60408" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the
  affected site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "affected", value: "ViArt CMS Version 3.6" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 's' parameter to 'admin/admin_articles.php' that allows the attackers
  to execute arbitrary HTML and script code in a logged-in user's browser session
  in context of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running ViArt CMS and is prone to cross site
  scripting vulnerability." );
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
for dir in nasl_make_list_unique( "/viart_shop", "/viart_cms", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/viart_shop.xml", port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, ">ViArt Shop PHP Shopping Cart<" )){
		ver = eregmatch( pattern: "<Program_Version>([0-9.]+)<", string: res );
		if(ver[1]){
			if(version_is_equal( version: ver[1], test_version: "3.6" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

