if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801793" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)" );
	script_bugtraq_id( 47790 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Calendarix Cross Site Scripting and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33876/" );
	script_xref( name: "URL", value: "http://securityreason.com/wlb_show/WLB-2011050051" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101295/calendarix-sqlxss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaws are due to:

  - Improper validation of user supplied input to '/cal_login.php' script.

  - Failure in the '/cal_date.php' script to properly sanitize user-supplied
  input in 'leftfooter' and 'frmname' variables.

  - Improper validation of user supplied input to '/cal_catview.php' via 'gocat'
  variable.

  - Failure in the 'cal_login.php' script to properly sanitize user-supplied
  input via 'login' field when 'password' field is set empty." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Calendarix and is prone to cross site scripting
  and SQL injection vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code and manipulate SQL queries by injecting arbitrary
  SQL code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Calendarix version 0.8.20080808." );
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
for path in nasl_make_list_unique( "/calendarix", "/", http_cgi_dirs( port: port ) ) {
	if(path == "/"){
		path = "";
	}
	res = http_get_cache( item: path + "/calendar.php", port: port );
	if(ContainsString( res, "About Calendarix" ) || ContainsString( res, "Calendarix version" )){
		url = NASLString( path, "/cal_login.php/'><script>alert('" + vt_strings["default"] + "');</script>" );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "><script>alert('" + vt_strings["default"] + "');</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

