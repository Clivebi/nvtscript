CPE = "cpe:/h:cisco:web_security_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106455" );
	script_cve_id( "CVE-2016-6469" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco Web Security Appliance HTTP URL Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-wsa" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in HTTP URL parsing of Cisco AsyncOS for Cisco Web Security
Appliance (WSA) could allow an unauthenticated, remote attacker to cause a denial of service (DoS) vulnerability
due to the proxy process unexpectedly restarting." );
	script_tag( name: "insight", value: "The vulnerability is due to improper input validation of the HTTP URL string.
An attacker could exploit this vulnerability by sending a crafted HTTP request to the affected device." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a DoS condition due to the proxy
process restarting." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-12-08 11:24:12 +0700 (Thu, 08 Dec 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wsa_version.sc" );
	script_mandatory_keys( "cisco_wsa/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "9.0.1-162",
	 "9.1.1-074" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

