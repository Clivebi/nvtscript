CPE = "cpe:/a:phpbb:phpbb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13840" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2054", "CVE-2004-2055" );
	script_bugtraq_id( 10738, 10753, 10754, 10883 );
	script_xref( name: "OSVDB", value: "8164" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "phpBB < 2.0.10 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "phpbb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpBB/installed" );
	script_tag( name: "solution", value: "Upgrade to 2.0.10 or later." );
	script_tag( name: "summary", value: "The remote host is running a version of phpBB older than 2.0.10.

  phpBB contains a flaw that allows a remote cross site scripting attack.
  This flaw exists because the application does not validate user-supplied
  input in the 'search_author' parameter.

  This version is also vulnerable to a HTTP response splitting vulnerability
  which permits the injection of CRLF characters in the HTTP headers." );
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
if(ereg( pattern: "^([01]\\.|2\\.0\\.[0-9]([^0-9]|$))", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.0.10" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

