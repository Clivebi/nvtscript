CPE = "cpe:/h:cisco:email_security_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140024" );
	script_cve_id( "CVE-2016-6358" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco Email Security Appliance FTP Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-esa6" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in local FTP to the Cisco Email Security Appliance (ESA) could allow an
  unauthenticated, remote attacker to cause a partial denial of service (DoS) condition when the FTP
  application unexpectedly quits.

  The vulnerability is due to improper input validation of user-supplied fields when logging in using
  FTP. An attacker could exploit this vulnerability by opening an FTP connection to the targeted
  device and crafting user-supplied parameters. An exploit could allow the attacker to cause a
  partial DoS condition when the FTP process unexpectedly quits. This vulnerability does not impact
  other user traffic.

  Cisco has released software updates that address this vulnerability. There are no workarounds that
  address this vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-10-27 14:08:43 +0200 (Thu, 27 Oct 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_esa_version.sc" );
	script_mandatory_keys( "cisco_esa/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "9.9.0",
	 "9.9.6-026",
	 "9.7.1-066",
	 "9.7.2-046  ",
	 "9.7.2-047",
	 "9.7.2-054 " );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

