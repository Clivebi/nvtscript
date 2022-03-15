if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100303" );
	script_version( "2021-01-13T07:27:23+0000" );
	script_tag( name: "last_modification", value: "2021-01-13 07:27:23 +0000 (Wed, 13 Jan 2021)" );
	script_tag( name: "creation_date", value: "2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)" );
	script_bugtraq_id( 36226 );
	script_cve_id( "CVE-2009-3062" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP Live! 'deptid' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36226" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "phplive_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phplive/detected" );
	script_tag( name: "summary", value: "PHP Live! is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "PHP Live! 3.3 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/phplive" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
vers = matches[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(version_is_equal( version: vers, test_version: "3.3" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

