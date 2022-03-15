if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903025" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-04-30 12:42:29 +0530 (Mon, 30 Apr 2012)" );
	script_name( "HelpDesk Multiple Persistent Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://1337day.com/exploits/18145" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "HelpDesk" );
	script_tag( name: "insight", value: "The flaws are due to improper validation of user supplied input
  passed via the 'searchvalue' parameter to 'knowledgebase.php' and 'client_name' parameter to
  'register.php', which allows attackers to execute arbitrary HTML and script code in the context
  of an affected application or site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running HelpDesk and is prone to multiple persistent
  cross site scripting vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/", "/helpdesk", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( buf, ">HelpDesk" ) && ContainsString( buf, "Powered by <" )){
		url = dir + "/knowledgebase.php?act=search&searchvalue=\"><script>alert" + "(document.cookie)</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, extra_check: "HelpDesk", pattern: "><script>alert\\(document.cookie\\)</script>" )){
			report = http_report_vuln_url( url: url, port: port );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

