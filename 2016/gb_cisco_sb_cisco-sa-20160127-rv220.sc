CPE = "cpe:/h:cisco:small_business";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105792" );
	script_cve_id( "CVE-2015-6319" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco RV220W Management Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160127-rv220" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web-based management interface of Cisco RV220W Wireless Network Security
  Firewall devices could allow an unauthenticated, remote attacker to bypass authentication and gain
  administrative privileges on a targeted device.

  The vulnerability is due to insufficient input validation of HTTP request headers that are sent to
  the web-based management interface of an affected device. An unauthenticated, remote attacker could
  exploit this vulnerability by sending a crafted HTTP request that contains malicious SQL statements
  to the management interface of a targeted device. Depending on whether remote management is
  configured for the device, the management interface may use the SQL code in the HTTP request header
  to determine user privileges for the device. A successful exploit could allow the attacker to bypass
  authentication on the management interface and gain administrative privileges on the device.

  Cisco released a firmware update that addresses this vulnerability. There are workarounds that
  address this vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-07-05 13:49:18 +0200 (Tue, 05 Jul 2016)" );
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
if(model == "RV220W"){
	affected = make_list( "1.0.0.2",
		 "1.0.0.30",
		 "1.0.1.9",
		 "1.0.2.6",
		 "1.0.3.10",
		 "1.0.4.10",
		 "1.0.4.14",
		 "1.0.5.4(GD)",
		 "1.0.5.6",
		 "1.0.5.8",
		 "1.0.6.6",
		 "1.1.0.9",
		 "1.2.0.2" );
}
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

