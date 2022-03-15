CPE = "cpe:/o:cisco:ios_xr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106927" );
	script_cve_id( "CVE-2017-6731" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_name( "Cisco IOS XR Software Multicast Source Discovery Protocol Session Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170705-iosxr" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in Multicast Source Discovery Protocol (MSDP) ingress packet
processing for Cisco IOS XR Software could allow an unauthenticated, remote attacker to cause the MSDP session to
be unexpectedly reset, causing a short denial of service (DoS) condition. The MSDP session will restart within a
few seconds." );
	script_tag( name: "insight", value: "The vulnerability is due to incorrect error handling of an MSDP packet that
contains an error in the packet header. An attacker could exploit this vulnerability by sending a malformed MSDP
packet for an established MSDP session to the targeted device." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a short DoS condition if the
MSDP session restarts." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-16 23:31:00 +0000 (Sun, 16 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-07-06 10:55:30 +0700 (Thu, 06 Jul 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xr_version.sc" );
	script_mandatory_keys( "cisco/ios_xr/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "4.3.2",
	 "6.0.2" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

