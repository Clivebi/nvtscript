if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801990" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)" );
	script_cve_id( "CVE-2010-4851", "CVE-2010-4852" );
	script_bugtraq_id( 45124 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Eclime Multiple SQL Injection and Cross-site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15644/" );
	script_xref( name: "URL", value: "http://securityreason.com/securityalert/8399" );
	script_xref( name: "URL", value: "https://www.htbridge.ch/advisory/sql_injection_in_eclime.html" );
	script_xref( name: "URL", value: "https://www.htbridge.ch/advisory/sql_injection_in_eclime_1.html" );
	script_xref( name: "URL", value: "https://www.htbridge.ch/advisory/sql_injection_in_eclime_2.html" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary
  script code or to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Eclime version 1.1.2b" );
	script_tag( name: "insight", value: "Multiple flaws are due to an:

  - Input passed via the parameters 'ref', ' poll_id' in 'index.php' and the
  parameter 'country' in 'create_account.php' script is not properly
  sanitised before being used in SQL queries.

  - Input passed via the parameter 'login' in 'login.php' script is not
  sanitized allowing the attacker to execute HTML code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Eclime and is prone to multiple cross site
  scripting and SQL injection vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_active" );
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
for dir in nasl_make_list_unique( "/eclime", "/eclime/catalog", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, ">eclime</" ) && ContainsString( res, "> e-commerce software.<" )){
		url = dir + "/login.php?login=fail&reason=<script>alert(document.cookie);</script>";
		if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(document\\.cookie\\);</script>", check_header: TRUE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
		url = dir + "/?ref='";
		if(http_vuln_check( port: port, url: url, pattern: "You have an error in your SQL syntax;" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

