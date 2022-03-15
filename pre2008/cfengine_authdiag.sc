CPE = "cpe:/a:gnu:cfengine";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14314" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1701", "CVE-2004-1702" );
	script_bugtraq_id( 10899, 10900 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "cfengine AuthenticationDialogue vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Denial of Service" );
	script_dependencies( "cfengine_detect.sc" );
	script_mandatory_keys( "cfengine/running" );
	script_tag( name: "solution", value: "Upgrade to 2.1.8 or newer." );
	script_tag( name: "summary", value: "Cfengine is running on this remote host.

  cfengine cfservd is reported prone to a remote heap-based buffer
  overrun vulnerability.

  The vulnerability presents itself in the cfengine cfservd
  AuthenticationDialogue() function. The issue exists due to a
  lack of sufficient boundary checks performed on challenge data
  that is received from a client.

  In addition, cfengine cfservd is reported prone to a remote denial
  of service vulnerability. The vulnerability presents itself in the cfengine
  cfservd AuthenticationDialogue() function which is responsible for processing
  SAUTH commands and also performing RSA based authentication.  The vulnerability
  presents itself because return values for several statements within the
  AuthenticationDialogue() function are not checked." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.8" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

