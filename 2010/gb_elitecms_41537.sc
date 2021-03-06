CPE = "cpe:/a:elitecms:elitecms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100711" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-07-13 12:45:31 +0200 (Tue, 13 Jul 2010)" );
	script_bugtraq_id( 41537 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "eliteCMS Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/41537" );
	script_xref( name: "URL", value: "http://elitecms.elite-graphix.net/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "eliteCMS_detect.sc" );
	script_mandatory_keys( "elitecms/installed" );
	script_tag( name: "summary", value: "eliteCMS is prone to multiple cross-site scripting vulnerabilities because it
fails to properly sanitize user-supplied input before using it in dynamically generated content.

An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in
the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and
launch other attacks.

eliteCMS 1.01 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "1.01" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

