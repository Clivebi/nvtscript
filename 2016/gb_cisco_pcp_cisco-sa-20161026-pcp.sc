CPE = "cpe:/a:cisco:prime_collaboration_provisioning";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107074" );
	script_cve_id( "CVE-2016-6451" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 11922 $" );
	script_name( "Cisco Prime Collaboration Provisioning Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-pcp" );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by convincing the user to access
a malicious link or by intercepting the user request and injecting malicious code. An exploit could allow the
attacker to execute arbitrary script code in the context of the affected site or allow the attacker to access
sensitive browser-based information." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation of some parameters
passed to the web server." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "Multiple vulnerabilities in the web framework code of the Cisco Prime
Collaboration Provisioning could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS)
attack against the user of the web interface of the affected system." );
	script_tag( name: "affected", value: "Cisco Prime Collaboration Provisioning version 10.6.0 is vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-10-28 15:41:14 +0200 (Fri, 28 Oct 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_pcp_version.sc" );
	script_mandatory_keys( "cisco_pcp/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
v = split( buffer: vers, sep: ".", keep: FALSE );
if(max_index( v ) < 4){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^10\\.6\\.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

