CPE = "cpe:/a:icecast:icecast";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15400" );
	script_version( "$Revision: 12219 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-06 03:43:55 +0100 (Tue, 06 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2933 );
	script_cve_id( "CVE-2001-1083" );
	script_xref( name: "OSVDB", value: "5472" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "ICECast crafted URL DoS" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_icecast_detect.sc" );
	script_mandatory_keys( "icecast/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 1.3.11 or later." );
	script_tag( name: "summary", value: "The remote server runs a version of ICECast, an open source streaming audio
server, which is older than version 1.3.11.

This version is affected by a remote denial of service because Icecast server does not properly sanitize
user-supplied input.

An remote attacker could send specially crafted URL, by adding '/', '\\' or '.' to the end, that may result in a
loss of availability for the service." );
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
if(version_is_less( version: version, test_version: "1.3.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.11" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

