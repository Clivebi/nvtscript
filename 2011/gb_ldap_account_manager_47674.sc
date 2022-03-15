if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103159" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-05-03 13:15:04 +0200 (Tue, 03 May 2011)" );
	script_bugtraq_id( 47674 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "LDAP Account Manager 'selfserviceSaveOk' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/47674" );
	script_xref( name: "URL", value: "http://www.autosectools.com/Advisory/LDAP-Account-Manager-3.4.0-Reflected-Cross-site-Scripting-193" );
	script_xref( name: "URL", value: "http://lam.sourceforge.net/index.htm" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_ldap_account_manager_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ldap_account_manager/installed" );
	script_tag( name: "summary", value: "LDAP Account Manager is prone to a cross-site scripting vulnerability
  because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks." );
	script_tag( name: "affected", value: "LDAP Account Manager 3.4.0 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "ldap_account_manager" )){
	exit( 0 );
}
url = NASLString( dir, "/templates/login.php?selfserviceSaveOk=<script>alert(/vt-xss-test/)</script>" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/vt-xss-test/\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

