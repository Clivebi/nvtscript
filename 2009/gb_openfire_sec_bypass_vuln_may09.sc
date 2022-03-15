CPE = "cpe:/a:igniterealtime:openfire";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800718" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1595", "CVE-2009-1596" );
	script_bugtraq_id( 34804 );
	script_name( "Openfire Security Bypass Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openfire_detect.sc" );
	script_require_ports( "Services/www", 9090 );
	script_mandatory_keys( "OpenFire/Installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34976" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34984" );
	script_xref( name: "URL", value: "http://www.igniterealtime.org/issues/browse/JM-1532" );
	script_xref( name: "URL", value: "http://www.igniterealtime.org/issues/browse/JM-1531" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34984" );
	script_xref( name: "URL", value: "http://www.igniterealtime.org/issues/browse/JM-1532" );
	script_tag( name: "summary", value: "This host is running Openfire, which is prone to multiple security bypass
  vulnerabilities." );
	script_tag( name: "impact", value: "Prior to version 3.6.4:

  Successful exploitation will let the attacker change the passwords of
  arbitrary accounts via a modified username element in a passwd_change
  action or can bypass intended policy and change their own passwords via
  a passwd_change IQ packet.

  Prior to version 3.6.5:

  Successful exploitation will let the attacker bypass intended policy
  and change their own passwords via a passwd_change IQ packet." );
	script_tag( name: "affected", value: "Openfire prior to 3.6.4 and prior to 3.6.5." );
	script_tag( name: "solution", value: "Upgrade to Openfire 3.6.4 or later." );
	script_tag( name: "insight", value: "- An error exists in the 'jabber:iq:auth' implementation in the
  IQAuthHandler.java File via a modified username element in a passwd_change action.

  - An error due to improper implementation of 'register.password' console configuration
  settings via a passwd_change IQ packet." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less( version: vers, test_version: "3.6.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.6.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

