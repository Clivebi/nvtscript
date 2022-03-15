CPE = "cpe:/a:phpbb:phpbb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20379" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 16088 );
	script_name( "phpBB <= 2.0.18 Multiple Cross-Site Scripting Flaws" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2006 David Maciejak" );
	script_dependencies( "phpbb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpBB/installed" );
	script_xref( name: "URL", value: "http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040204.html" );
	script_xref( name: "URL", value: "http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=352966" );
	script_tag( name: "impact", value: "This may allow an attacker to inject hostile Javascript into
  the forum system, to steal cookie credentials or misrepresent site content. When the form is
  submitted the malicious Javascript will be incorporated into dynamically generated content." );
	script_tag( name: "solution", value: "Upgrade to phpBB version 2.0.19 or later." );
	script_tag( name: "summary", value: "The remote web server contains a PHP application that is affected by
  several flaws.

  Description :

  According to its version number, the remote version of this software
  is vulnerable to Javascript injection issues using 'url' bbcode tags
  and, if HTML tags are enabled, HTML more generally." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(ereg( pattern: "^([01]\\..*|2\\.0\\.([0-9]|1[0-8])[^0-9])", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.0.19" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

