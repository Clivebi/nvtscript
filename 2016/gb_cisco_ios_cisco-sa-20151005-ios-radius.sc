CPE = "cpe:/o:cisco:ios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105635" );
	script_cve_id( "CVE-2015-6263" );
	script_tag( name: "cvss_base", value: "6.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:C" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco IOS Software RADIUS Client Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151005-ios-radius" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the RADIUS client feature of Cisco IOS Software could allow an authenticated,
  remote attacker to cause a reload of the affected device.

  The vulnerability is due to improper parsing of malformed RADIUS packets returned by a RADIUS server.
  An attacker could exploit this vulnerability by configuring a RADIUS server with a shared RADIUS secret and returning malformed
  answers back to a RADIUS client on an affected Cisco device. An exploit could allow the attacker to cause a reload of the affected device.

  Cisco has released software updates that address this vulnerability. Workarounds that mitigate this vulnerability are not available.
  This advisory is available at the references." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-05-03 18:59:17 +0200 (Tue, 03 May 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_cisco_ios_get_version.sc" );
	script_mandatory_keys( "cisco_ios/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "15.4(3)M2.2" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

