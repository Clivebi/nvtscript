CPE = "cpe:/o:cisco:nx-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106338" );
	script_cve_id( "CVE-2016-1455" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco Nexus 9000 Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-n9kinfo" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the internal iptables configuration for local interfaces
on the Cisco Nexus 9000 Series Switch could allow an unauthenticated, remote attacker to access certain sensitive
data. The attacker could use this information to conduct additional reconnaissance attacks." );
	script_tag( name: "insight", value: "The vulnerability is due to incorrect filtering of network traffic destined
to certain TCP and UDP ports configured on a local interface. An attacker could exploit this vulnerability by
connecting to the affected device on one of the exposed TCP or UDP ports." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to discover certain sensitive data which
should be restricted and could be used to conduct further attacks." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-10-06 11:39:53 +0700 (Thu, 06 Oct 2016)" );
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
	affected = make_list( "7.0(3)",
		 "7.0(3)I1(1)",
		 "7.0(3)I1(1a)",
		 "7.0(3)I1(1b)",
		 "7.0(3)I1(2)" );
}
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

