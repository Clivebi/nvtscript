CPE = "cpe:/a:basilix:basilix_webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14306" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-1711" );
	script_bugtraq_id( 5065 );
	script_name( "BasiliX Attachment Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2004 George A. Theall" );
	script_dependencies( "basilix_detect.sc" );
	script_mandatory_keys( "basilix/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to BasiliX version 1.1.1 or later." );
	script_tag( name: "summary", value: "The remote web server contains a series of PHP scripts that are prone to
information disclosure.

Description :

The remote host appears to be running a BasiliX version 1.1.0 or lower. Such versions save attachments by default
under '/tmp/BasiliX', which is world-readable and apparently never emptied by BasiliX itself.  As a result, anyone
with shell access on the affected system or who can place CGI files on it can access attachments uploaded to
BasiliX." );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0117.html" );
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
if(version_is_less( version: version, test_version: "1.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

