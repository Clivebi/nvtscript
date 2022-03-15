CPE = "cpe:/a:ipswitch:imail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901195" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)" );
	script_cve_id( "CVE-2011-1430" );
	script_bugtraq_id( 46767 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Ipswitch IMail Server STARTTLS Plaintext Command Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "SMTP problems" );
	script_dependencies( "gb_ipswitch_imail_server_detect.sc" );
	script_mandatory_keys( "Ipswitch/IMail/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43676" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/060" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  commands in the context of the user running the application." );
	script_tag( name: "affected", value: "Ipswitch IMail versions 11.03 and Prior." );
	script_tag( name: "insight", value: "This flaw is caused by an error within the 'STARTTLS'
  implementation where the switch from plaintext to TLS is implemented below the
  application's I/O buffering layer, which could allow attackers to inject
  commands during the  plaintext phase of the protocol via man-in-the-middle
  attacks." );
	script_tag( name: "solution", value: "Upgrade to Ipswitch IMail version 11.5 or later." );
	script_tag( name: "summary", value: "The host is running Ipswitch IMail Server and is prone to
  plaintext command injection vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.imailserver.com/" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "11.03" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

