CPE = "cpe:/a:cisco:unified_communications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106780" );
	script_cve_id( "CVE-2017-3808" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_name( "Cisco Unified Communications Manager Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-ucm" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Session Initiation Protocol (SIP) UDP throttling
process of Cisco Unified Communications Manager (Cisco Unified CM) could allow an unauthenticated, remote
attacker to cause a denial of service (DoS) condition on an affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient rate limiting protection. An
attacker could exploit this vulnerability by sending the affected device a high rate of SIP messages." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause the device to reload
unexpectedly. The device and services will restart automatically." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-04-20 16:25:38 +0200 (Thu, 20 Apr 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_cucm_version.sc" );
	script_mandatory_keys( "cisco/cucm/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
version = str_replace( string: version, find: "-", replace: "." );
affected = make_list( "10.0.1.10000.12",
	 "10.5.0.98000.88",
	 "10.5.1.98991.13",
	 "10.5.1.99995.9",
	 "10.5.2.10000.5",
	 "10.5.2.12901.1",
	 "10.5.2.13900.9",
	 "10.5.3.10000.9",
	 "11.0.0.98000.225",
	 "11.0.1.10000.10",
	 "11.5.0.98000.480",
	 "11.5.0.98000.486",
	 "11.5.0.99838.4",
	 "11.5.1.10000.6",
	 "11.5.1.11007.2",
	 "11.5.1.12000.1",
	 "11.5.1.2",
	 "11.5.0" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

