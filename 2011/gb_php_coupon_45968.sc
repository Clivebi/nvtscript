if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103043" );
	script_version( "2021-03-11T10:58:32+0000" );
	script_tag( name: "last_modification", value: "2021-03-11 10:58:32 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "creation_date", value: "2011-01-25 13:20:03 +0100 (Tue, 25 Jan 2011)" );
	script_bugtraq_id( 45968 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP Coupon Script 'page' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45968" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "PHP Coupon Script is prone to an SQL-injection
  vulnerability because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "Attackers may exploit this issue to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the
  underlying database." );
	script_tag( name: "affected", value: "PHP Coupon Script 6.0 is vulnerable. Other versions
  may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
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
for dir in nasl_make_list_unique( "/phpcoupon", "/coupon", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	if(!res || !IsMatchRegexp( res, " alt=\"(PHP )?Coupon Script\"" )){
		continue;
	}
	url = dir + "/index.php?page=viewbus&bus='";
	if(http_vuln_check( port: port, url: url, pattern: "You have an error in your SQL syntax" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

