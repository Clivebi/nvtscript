if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103404" );
	script_bugtraq_id( 38201 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2010-0641" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Cisco Collaboration Server 'LoginPage.jhtml' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38201" );
	script_xref( name: "URL", value: "http://www.cisco.com/en/US/products/sw/custcosw/ps747/prod_eol_notice09186a008032d4d0.html" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-01-27 13:46:02 +0100 (Fri, 27 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Cisco Collaboration Server is prone to a cross-site scripting
vulnerability because it fails to properly sanitize user-
supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Cisco Collaboration Server 5 is vulnerable. Other versions may be
affected as well.

NOTE: The vendor has discontinued this product." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
 disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
 to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/webline/html/admin/wcs/LoginPage.jhtml?oper=login&dest=%2Fadmin%2FCiscoAdmin.jhtml";
if(http_vuln_check( port: port, url: url, pattern: "Cisco Administration Log In" )){
	url = "/webline/html/admin/wcs/LoginPage.jhtml?oper=&dest=\"><script>alert(/xss-test/)</script>";
	if(http_vuln_check( port: port, url: url, pattern: "script>alert\\(/xss-test/\\)</script>", check_header: TRUE )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

