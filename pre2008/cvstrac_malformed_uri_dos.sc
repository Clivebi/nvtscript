CPE = "cpe:/a:cvstrac:cvstrac";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14289" );
	script_version( "$Revision: 9336 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-04-05 16:02:17 +0200 (Thu, 05 Apr 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "OSVDB", value: "8646" );
	script_name( "CVSTrac malformed URI infinite loop DoS" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "cvstrac_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cvstrac/detected" );
	script_tag( name: "solution", value: "Update to version 1.1.4 or disable this CGI suite" );
	script_tag( name: "summary", value: "The remote host seems to be running cvstrac,
  a web-based bug and patch-set tracking system for CVS.

  This version contains a flaw related to the parameter parser
  that may allow an attacker to create a malformed URL,
  which causes the application to hang.  An attacker, exploiting
  this flaw, would only need network access to the cvstrac server.
  Upon sending a malformed link, the cvstrac server would go into
  an infinite loop, rendering the services as unavailable.

  ***** OpenVAS has determined the vulnerability exists on the target
  ***** simply by looking at the version number(s) of CVSTrac
  ***** installed there." );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(ereg( pattern: "^(0\\.|1\\.(0|1\\.[0-3]([^0-9]|$)))", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.1.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

