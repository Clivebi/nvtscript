if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103414" );
	script_bugtraq_id( 51874 );
	script_cve_id( "CVE-2012-1017" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_name( "BASE 'base_qry_main.php' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51874" );
	script_xref( name: "URL", value: "http://base.secureideas.net/" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-02-10 11:58:03 +0100 (Fri, 10 Feb 2012)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "base_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "BASE/installed" );
	script_tag( name: "summary", value: "BASE is prone to an SQL-injection vulnerability because it fails
to sufficiently sanitize user-supplied data before using it in an
SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database." );
	script_tag( name: "affected", value: "BASE 1.4.5 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:secureideas:base";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "1.4.5" )){
	security_message( port: port, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

