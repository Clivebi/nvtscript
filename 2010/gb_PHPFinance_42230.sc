if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100771" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-09-01 14:30:27 +0200 (Wed, 01 Sep 2010)" );
	script_bugtraq_id( 42230 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "PHPFinance 'group.php' SQL Injection and HTML Injection Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42230" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_PHPFinance_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpfinance/detected" );
	script_tag( name: "summary", value: "PHPFinance is prone to an SQL-injection vulnerability and an HTML-
  injection vulnerability because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may exploit the HTML-injection issue to execute arbitrary
  script code in the browser of an unsuspecting user in the context of
  the affected site. This may allow the attacker to steal cookie-based
  authentication credentials, control how the site is displayed, and
  launch other attacks.

  The attacker may exploit the SQL-injection issue to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database." );
	script_tag( name: "affected", value: "PHPFinance 0.6 is vulnerable. Other versions may also be affected." );
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
if(vers = get_version_from_kb( port: port, app: "phpfinance" )){
	if(version_is_equal( version: vers, test_version: "0.6" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

