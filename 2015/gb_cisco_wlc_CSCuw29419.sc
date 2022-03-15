CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105384" );
	script_cve_id( "CVE-2015-6302" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-06-02T09:00:58+0000" );
	script_tag( name: "last_modification", value: "2021-06-02 09:00:58 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2015-09-23 13:23:46 +0200 (Wed, 23 Sep 2015)" );
	script_name( "Cisco Wireless LAN Controller Radius Packet of Disconnect Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=41102" );
	script_tag( name: "summary", value: "Cisco Wireless LAN Controller contains a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service condition." );
	script_tag( name: "impact", value: "An unauthenticated, remote attacker could exploit this vulnerability to cause the vulnerable software on an affected device to disconnect user sessions, resulting in a DoS condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to a lack of proper input validation of the RADIUS Disconnect-Request packet. An attacker could exploit this vulnerability by sending crafted RADIUS UDP
Disconnect-Request packets to the affected device. An exploit could allow the attacker to cause a partial DoS condition due to the disconnect of random user sessions." );
	script_tag( name: "solution", value: "See vendor advisory for a solution" );
	script_tag( name: "affected", value: "Cisco Wireless LAN Controller Software 7.0(250.0) and 7.0(252.0)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wlc_consolidation.sc" );
	script_mandatory_keys( "cisco/wlc/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(vers == "7.0.250.0" || vers == "7.0.252.0"){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

