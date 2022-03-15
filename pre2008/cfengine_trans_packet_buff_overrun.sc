CPE = "cpe:/a:gnu:cfengine";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14317" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 8699 );
	script_cve_id( "CVE-2003-0849" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "cfengine CFServD transaction packet buffer overrun vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "cfengine_detect.sc" );
	script_mandatory_keys( "cfengine/running" );
	script_tag( name: "solution", value: "Upgrade to at least 1.5.3-4, 2.0.8 or most recent 2.1 version." );
	script_tag( name: "summary", value: "Cfengine is running on this remote host.

  This version is prone to a stack-based buffer overrun vulnerability.
  An attacker, exploiting this flaw, would need network access to the
  server as well as the ability to send a crafted transaction packet
  to the cfservd process. A successful exploitation of this flaw
  would lead to arbitrary code being executed on the remote machine
  or a loss of service (DoS)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.0.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.8" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

