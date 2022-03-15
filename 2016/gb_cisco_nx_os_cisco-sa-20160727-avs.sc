CPE = "cpe:/o:cisco:nx-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105836" );
	script_cve_id( "CVE-2016-1465" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_name( "Cisco Nexus 1000v Application Virtual Switch Cisco Discovery Protocol Packet Processing Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160727-avs" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in Cisco Discovery Protocol packet processing for the Cisco Nexus 1000v Application
Virtual Switch (AVS) could allow an unauthenticated, remote attacker to cause the ESXi hypervisor to
crash and display a purple diagnostic screen, resulting in a denial of service (DoS) condition.

The vulnerability is due to insufficient input validation of Cisco Discovery Protocol packets, which
could result in a crash of the ESXi hypervisor due to an out-of-bound memory access. An attacker
could exploit this vulnerability by sending a crafted Cisco Discovery Protocol packet to a targeted
device. An exploit could allow the attacker to cause a DoS condition.

Cisco has released software updates that address this vulnerability. Workarounds that address this
vulnerability are not available." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)" );
	script_tag( name: "creation_date", value: "2016-07-29 18:14:02 +0200 (Fri, 29 Jul 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(ContainsString( nx_model, "1000V" )){
	affected = make_list( "4.0(4)SV1(1)",
		 "4.0(4)SV1(2)",
		 "4.0(4)SV1(3)",
		 "4.0(4)SV1(3a)",
		 "4.0(4)SV1(3b)",
		 "4.0(4)SV1(3c)",
		 "4.0(4)SV1(3d)",
		 "4.2(1)SV1(4)",
		 "4.2(1)SV1(4a)",
		 "4.2(1)SV1(4b)",
		 "4.2(1)SV1(5.1)",
		 "4.2(1)SV1(5.1a)",
		 "4.2(1)SV1(5.2)",
		 "4.2(1)SV1(5.2b)",
		 "4.2(1)SV2(1.1)",
		 "4.2(1)SV2(1.1a)",
		 "4.2(1)SV2(2.1)",
		 "4.2(1)SV2(2.1a)",
		 "5.2(1)SV3(1.1)",
		 "5.2(1)SV3(1.3)",
		 "5.2(1)SV3(1.4)" );
}
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

