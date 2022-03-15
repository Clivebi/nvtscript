CPE = "cpe:/a:splunk:splunk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100694" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-07-05 12:40:56 +0200 (Mon, 05 Jul 2010)" );
	script_bugtraq_id( 41269 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Splunk Cross Site Scripting and Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/41269" );
	script_xref( name: "URL", value: "http://www.splunk.com/view/SP-CAAAFGD#31067" );
	script_xref( name: "URL", value: "http://www.splunk.com/" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_splunk_detect.sc" );
	script_mandatory_keys( "Splunk/installed" );
	script_tag( name: "summary", value: "Splunk is prone to multiple cross-site scripting vulnerabilities and multiple
directory-traversal vulnerabilities because it fails to sufficiently sanitize user-supplied input.

Exploiting these issues will allow an attacker to execute arbitrary script code in the browser of an unsuspecting
user in the context of the affected site, and to view arbitrary local files and directories within the context of
the webserver. This may let the attacker steal cookie-based authentication credentials and other harvested
information may aid in launching further attacks." );
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
if(version_in_range( version: version, test_version: "4.0", test_version2: "4.0.10" ) || version_in_range( version: version, test_version: "4.1", test_version2: "4.1.1" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

