if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902326" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)" );
	script_cve_id( "CVE-2010-4607", "CVE-2010-4608" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Habari Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42688" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15799/" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/xss_vulnerability_in_habari.html" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/xss_vulnerability_in_habari_1.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaws are due to

  - Input passed to the 'additem_form' parameter in 'system/admin/dash_additem.php'
    and 'status_data[]' parameter in 'system/admin/dash_status.php' is not
    properly sanitised before being returned to the user.

  - Error in '/system/admin/header.php' and '/system/admin/comments_items.php'
    script, which generate an error that will reveal the full path of the script." );
	script_tag( name: "solution", value: "Upgrade to Habari version 0.6.6 or later" );
	script_tag( name: "summary", value: "This host is running Habari and is prone to multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site and determine the full path to the web root directory and other potentially
  sensitive information." );
	script_tag( name: "affected", value: "Habari version 0.6.5" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://habariproject.org/en/download" );
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
for dir in nasl_make_list_unique( "/habari", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( res, "<title>My Habari</title>" )){
		req = http_get( item: NASLString( dir, "/system/admin/dash_status.php?status_data" + "[1]=<script>alert(\"" + vt_strings["default"] + "\");</script>" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ereg( pattern: "^HTTP/1\\.[01] 200", string: res ) && ContainsString( res, "<script>alert(\"" + vt_strings["default"] + "\");</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

