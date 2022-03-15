if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803440" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-03-18 14:25:41 +0530 (Mon, 18 Mar 2013)" );
	script_name( "ClipShare Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24790" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120792/" );
	script_xref( name: "URL", value: "http://www.exploitsdownload.com/exploit/na/clipshare-414-sql-injection-plaintext-password" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain
  access to the password information and inject or manipulate SQL queries in the
  back-end database, allowing for the manipulation or disclosure of arbitrary
  data." );
	script_tag( name: "affected", value: "ClipShare Version 4.1.4" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - storing sensitive information in the /siteadmin/login.php file as plaintext

  - Input passed via the 'urlkey' parameter to ugroup_videos.php script is not
  properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with ClipShare and is prone to Multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/", "/clipshare", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, ">ClipShare<" )){
		url = dir + "/ugroup_videos.php?urlkey=1' or (select if(5=5,0,3))-- 3='3";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: ">ClipShare<" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

