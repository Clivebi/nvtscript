if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100817" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-21 16:24:40 +0200 (Tue, 21 Sep 2010)" );
	script_bugtraq_id( 43330 );
	script_cve_id( "CVE-2010-3485", "CVE-2010-3484" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "LightNEasy 'LightNEasy.php' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43330" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_lightneasy_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lightneasy/detected" );
	script_tag( name: "summary", value: "LightNEasy is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "LightNEasy 3.2.1 is vulnerable, other versions may also be affected." );
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
if(vers = get_version_from_kb( port: port, app: NASLString( "LightNEasy/Sqlite" ) )){
	if(version_is_equal( version: vers, test_version: "3.2.1" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

