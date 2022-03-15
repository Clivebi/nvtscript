CPE = "cpe:/a:cisco:meeting_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140046" );
	script_cve_id( "CVE-2016-6444" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco Meeting Server Cross-Site Request Forgery Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161019-cms" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in Cisco Meeting Server could allow an unauthenticated, remote attacker to conduct a
cross-site request forgery (CSRF) attack against a Web Bridge user.

The vulnerability is due to insufficient CSRF protections. An attacker could exploit this
vulnerability by convincing the user of the affected system to follow a malicious link or visit an
attacker-controlled website. A successful exploit could allow an attacker to submit arbitrary
requests to the affected device via the Web Bridge with the privileges of the user.

Cisco has released software updates that address this vulnerability. Workarounds that address this
vulnerability are not available." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-11-02 16:22:08 +0100 (Wed, 02 Nov 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_meeting_server_snmp_detect.sc" );
	script_mandatory_keys( "cisco/meeting_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "1.8.0",
	 "1.8.15",
	 "1.9.0",
	 "1.9.2",
	 "2.0.0",
	 "2.0.1",
	 "2.0.3",
	 "2.0.4",
	 "2.0.5" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

