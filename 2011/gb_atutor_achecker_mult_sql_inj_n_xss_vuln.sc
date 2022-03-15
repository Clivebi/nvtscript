if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801982" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)" );
	script_bugtraq_id( 49061, 49093 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Atutor AChecker Multiple SQL Injection and XSS Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17630/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103763/ZSL-2011-5035.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103762/ZSL-2011-5034.txt" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary
  script code or to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Atutor AChecker 1.2 (build r530)." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - input passed via the parameter 'myown_patch_id' in '/updater/patch_edit.php'
  and the parameter 'id' in '/user/user_create_edit.php' script is not
  properly sanitised before being used in SQL queries.

  - input through the GET parameters 'id', 'p' and 'myown_patch_id' in
  multiple scripts is not sanitized allowing the attacker to execute HTML
  code or disclose the full path of application's residence." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Atutor AChecker and is prone to multiple
  cross site scripting and SQL injection vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in make_list( "/AChecker",
	 "/" ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/checker/index.php";
	res = http_get_cache( item: url, port: port );
	if(res && ContainsString( res, "Web Accessibility Checker<" ) && ContainsString( res, ">Check Accessibility" )){
		url = dir + "/documentation/frame_header.php?p=\"><script>alert(document.cookie)</script>";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "\"><script>alert(document.cookie)</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
		url = dir + "/user/user_create_edit.php?id='1111";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "You have an error in your SQL syntax;" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

