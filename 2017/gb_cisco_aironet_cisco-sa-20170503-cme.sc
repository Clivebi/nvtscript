CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106803" );
	script_cve_id( "CVE-2017-3873" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_name( "Cisco Aironet 1800, 2800, and 3800 Series Access Points Plug-and-Play Arbitrary Code Execution Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170503-cme" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 8.3.112.0 or later." );
	script_tag( name: "summary", value: "A vulnerability in the Plug-and-Play (PnP) subsystem of the Cisco Aironet
1800, 2800, and 3800 Series Access Points running a Lightweight Access Point (AP) or Mobility Express image could
allow an unauthenticated, adjacent attacker to execute arbitrary code with root privileges." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient validation of PnP server responses.
The PnP feature is only active while the device does not contain a configuration, such as a first time boot or
after a factory reset has been issued. An attacker with the ability to respond to PnP configuration requests from
the affected device can exploit the vulnerability by returning malicious PnP responses. If a Cisco Application
Policy Infrastructure Controller - Enterprise Module (APIC-EM) is available on the network, the attacker would
need to exploit the issue in the short window before a valid PnP response was received." );
	script_tag( name: "impact", value: "If successful, the attacker could gain the ability to execute arbitrary code
with root privileges on the underlying operating system of the device." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-05-10 22:11:53 +0700 (Wed, 10 May 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wlc_consolidation.sc" );
	script_mandatory_keys( "cisco/wlc/detected", "cisco/wlc/model" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
model = get_kb_item( "cisco/wlc/model" );
if(!model || !IsMatchRegexp( model, "^AIR-AP(1|2|3)8[0-9]{2}" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version == "8.3.102.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.3.112.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

