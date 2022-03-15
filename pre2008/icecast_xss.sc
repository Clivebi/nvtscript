CPE = "cpe:/a:icecast:icecast";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14390" );
	script_version( "$Revision: 12219 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-06 03:43:55 +0100 (Tue, 06 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 11021 );
	script_cve_id( "CVE-2004-0781" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "ICECast XSS" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_icecast_detect.sc" );
	script_mandatory_keys( "icecast/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 1.3.12 or later." );
	script_tag( name: "summary", value: "The remote server runs a version of ICECast which is as old as or older than
version 1.3.12.

This version is affected by a cross-site scripting vulnerability in the status display functionality. This issue
is due to a failure of the application to properly sanitize user-supplied input.

As a result of this vulnerability, it is possible for a remote attacker to create a malicious link containing
script code that will be executed in the browser of an unsuspecting user when followed.

This may facilitate the theft of cookie-based authentication credentials as well as other attacks." );
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
if(version_is_less( version: version, test_version: "1.3.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.12" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

