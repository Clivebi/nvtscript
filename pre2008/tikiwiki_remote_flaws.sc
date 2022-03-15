CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16229" );
	script_version( "$Revision: 5144 $" );
	script_bugtraq_id( 12328 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2017-01-31 10:55:46 +0100 (Tue, 31 Jan 2017) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Tiki Wiki CMS Groupware multiple remote unspecified flaws" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TikiWiki/installed" );
	script_xref( name: "URL", value: "http://tiki.org/art102" );
	script_tag( name: "solution", value: "Upgrade to latest version" );
	script_tag( name: "impact", value: "This flaws may allow an attacker to execute arbitrary PHP script code on the hosting
  web server." );
	script_tag( name: "summary", value: "The remote host is running Tiki Wiki CMS Groupware, a content management system written
  in PHP.

  The remote version of this software is vulnerable to multiple flaws." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(egrep( pattern: "(0\\.|1\\.[0-7]\\.|1\\.8\\.[0-5][^0-9]|1\\.9 RC(1|2|3|3\\.1)([^.]|[^0-9]))", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See vendor advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

