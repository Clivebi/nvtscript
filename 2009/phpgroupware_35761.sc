if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100237" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-07-22 19:53:45 +0200 (Wed, 22 Jul 2009)" );
	script_cve_id( "CVE-2009-4414" );
	script_bugtraq_id( 35761 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "phpGroupWare Multiple Input Validation Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/35761" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "phpgroupware_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpGroupWare/installed" );
	script_tag( name: "summary", value: "phpGroupWare is prone to multiple input-validation vulnerabilities
  because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to disclose sensitive
  information, steal cookie-based authentication credentials, compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "phpGroupWare 0.9.16.12 is affected, other versions may also be
  vulnerable." );
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
if(!version = get_kb_item( NASLString( "www/", port, "/phpGroupWare" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
vers = matches[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(version_is_equal( version: vers, test_version: "0.9.16.12" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );
