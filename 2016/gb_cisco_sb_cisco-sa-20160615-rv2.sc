CPE = "cpe:/h:cisco:small_business";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105770" );
	script_cve_id( "CVE-2016-1397" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco RV110W, RV130W, and RV215W Routers HTTP Request Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160615-rv2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web-based management interface of Cisco RV110W Wireless-N VPN Firewalls,
Cisco RV130W Wireless-N Multifunction VPN Routers, and Cisco RV215W Wireless-N VPN Routers could
allow an authenticated, remote attacker to cause a buffer overflow on a targeted system, resulting
in a denial of service (DoS) condition.

The vulnerability is due to improper sanitization of user-supplied input for fields in HTTP requests
that are sent when a user configures an affected device by using the web-based management interface
for the device. An attacker could exploit this vulnerability by sending an HTTP request that
contains configuration commands with a crafted payload. A successful exploit could allow the
attacker to cause a buffer overflow on the targeted system, which could cause the device to reload
unexpectedly and result in a DoS condition." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-06-17 13:57:06 +0200 (Fri, 17 Jun 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_small_business_devices_snmp_detect.sc" );
	script_mandatory_keys( "cisco/small_business/model", "cisco/small_business/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(!model = get_kb_item( "cisco/small_business/model" )){
	exit( 0 );
}
if(model == "RV110W"){
	affected = make_list( "1.1.0.9",
		 "1.2.0.10",
		 "1.2.0.9",
		 "1.2.1.4" );
}
if(model == "RV130W"){
	affected = make_list( "1.0.0.21",
		 "1.0.1.3",
		 "1.0.2.7" );
}
if(model == "RV215W"){
	affected = make_list( "1.1.0.5",
		 "1.1.0.6",
		 "1.2.0.14",
		 "1.2.0.15",
		 "1.3.0.7" );
}
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

