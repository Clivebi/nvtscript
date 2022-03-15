CPE = "cpe:/a:ipswitch:imail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14684" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2422", "CVE-2004-2423" );
	script_bugtraq_id( 11106 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "ipswitch IMail DoS" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ipswitch_imail_server_detect.sc" );
	script_mandatory_keys( "Ipswitch/IMail/detected" );
	script_tag( name: "solution", value: "Upgrade to IMail 8.13 or newer." );
	script_tag( name: "summary", value: "The remote host is running IMail web interface. This version contains
  multiple buffer overflows." );
	script_tag( name: "impact", value: "An attacker could use these flaws to remotly crash the service
  accepting requests from users, or possibly execute arbitrary code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "8.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.13" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

