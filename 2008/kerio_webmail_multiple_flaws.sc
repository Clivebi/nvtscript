CPE = "cpe:/a:kerio:kerio_mailserver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80069" );
	script_version( "$Revision: 10785 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-06 11:58:05 +0200 (Mon, 06 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-1434", "CVE-2003-0487", "CVE-2003-0488" );
	script_bugtraq_id( 5507, 7966, 7967, 7968, 8230, 9975 );
	script_xref( name: "OSVDB", value: "2159" );
	script_xref( name: "OSVDB", value: "4953" );
	script_xref( name: "OSVDB", value: "4954" );
	script_xref( name: "OSVDB", value: "4955" );
	script_xref( name: "OSVDB", value: "4956" );
	script_xref( name: "OSVDB", value: "4958" );
	script_name( "Kerio WebMail v5 multiple flaws" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003-2007 Tenable Network Security & Copyright (C) 2004 David Maciejak" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_kerio_mailserver_detect.sc" );
	script_mandatory_keys( "KerioMailServer/detected" );
	script_tag( name: "solution", value: "Upgrade to Kerio MailServer 5.7.7 or newer" );
	script_tag( name: "summary", value: "The remote host is running version 5 of the Kerio MailServer.

  There are multiple flaws in this interface which may allow an attacker with a valid webmail account on this host
  to obtain a shell on this host or to perform a cross-site-scripting attack against this host with version prior to
  5.6.4.

  Version of MailServer prior to 5.6.5 are also prone to a denial of service condition when an incorrect login to
  the admin console occurs. This could cause the server to crash.

  Version of MailServer prior to 5.7.7 is prone to a remotely exploitable buffer overrun condition. This
  vulnerability exists in the spam filter component. If successfully exploited, this could permit remote attackers
  to execute arbitrary code in the context of the MailServer software. This could also cause a denial of service in
  the server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE, version_regex: "^5\\." )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "5.7.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.7.7" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

