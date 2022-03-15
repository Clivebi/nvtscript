if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103339" );
	script_bugtraq_id( 50632 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3829", "CVE-2011-3830", "CVE-2011-3831", "CVE-2011-3832", "CVE-2011-3833" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_name( "Support Incident Tracker (SiT!) Multiple Input Validation Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50632" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2011-78/" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2011-76/" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2011-79/" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2011-75/" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2011-77/" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-11-16 11:22:53 +0100 (Wed, 16 Nov 2011)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "support_incident_tracker_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sit/installed" );
	script_tag( name: "summary", value: "Support Incident Tracker (SiT!) is prone to the following input-
  validation vulnerabilities:

  1. A cross-site scripting vulnerability

  2. An SQL-injection vulnerability

  3. A PHP code-injection vulnerability

  4. A path-disclosure vulnerability

  5. An arbitrary-file-upload vulnerability" );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to execute arbitrary
  code, steal cookie-based authentication credentials, compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database. Access to sensitive data may also be used
  to launch further attacks against a vulnerable computer." );
	script_tag( name: "affected", value: "Support Incident Tracker (SiT!) 3.65 is vulnerable. Other versions may
  also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "support_incident_tracker" )){
	if(version_is_equal( version: vers, test_version: "3.65" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

