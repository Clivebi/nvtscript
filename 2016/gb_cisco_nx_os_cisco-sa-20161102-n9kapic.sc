CPE = "cpe:/o:cisco:nx-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106368" );
	script_cve_id( "CVE-2016-6457" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco Application Policy Infrastructure Controller Denial of Service Vulnerability (NX-OS)" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161102-n9kapic" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Cisco Nexus 9000 Series Platform Leaf Switches for
Application Centric Infrastructure (ACI) could allow an unauthenticated, adjacent attacker to cause a denial of
service (DoS) condition on the affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to improper handling of a type of Layer 2 control
plane traffic. An attacker could exploit this vulnerability by sending crafted traffic to a host behind a leaf
switch." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a DoS condition on the affected
device." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-11-03 13:46:04 +0700 (Thu, 03 Nov 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(!device = get_kb_item( "cisco_nx_os/device" )){
	exit( 0 );
}
if(!ContainsString( device, "Nexus" )){
	exit( 0 );
}
if(!nx_model = get_kb_item( "cisco_nx_os/model" )){
	exit( 0 );
}
if(IsMatchRegexp( nx_model, "^N9K" )){
	affected = make_list( "11.2(2g)",
		 "11.2(2h)",
		 "11.2(2i)",
		 "11.2(3c)",
		 "11.2(3e)",
		 "11.2(3h)",
		 "11.3(1i)",
		 "11.3(2f)",
		 "11.3(2h)",
		 "11.3(2i)",
		 "12.0(1m)",
		 "12.0(1n)",
		 "12.0(1o)",
		 "12.0(1p)",
		 "12.0(1q)" );
}
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

