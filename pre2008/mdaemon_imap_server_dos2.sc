CPE = "cpe:/a:alt-n:mdaemon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14827" );
	script_version( "2021-02-08T15:30:09+0000" );
	script_tag( name: "last_modification", value: "2021-02-08 15:30:09 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 2508 );
	script_cve_id( "CVE-2001-0584" );
	script_name( "MDaemon IMAP Server DoS(2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_altn_mdaemon_consolidation.sc" );
	script_mandatory_keys( "altn/mdaemon/detected" );
	script_tag( name: "solution", value: "Upgrade to the newest version of this software." );
	script_tag( name: "summary", value: "It is possible to crash the remote MDaemon IMAP server
  by sending a too long argument to the 'SELECT' or 'EXAMINE' commands." );
	script_tag( name: "impact", value: "This problem allows an attacker to make the remote
  MDaemon server to crash, thus preventing legitimate users from receiving e-mails." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^[0-5]\\.|6\\.[0-7]" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

