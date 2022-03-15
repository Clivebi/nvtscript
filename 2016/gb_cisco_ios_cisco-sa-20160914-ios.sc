CPE = "cpe:/o:cisco:ios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106249" );
	script_cve_id( "CVE-2016-6404" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 12313 $" );
	script_name( "Cisco IOS Software IOx Local Manager Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160914-ios" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web framework code of the Cisco Local Manager could
allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against the user of
the web interface of the affected system." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation of some
parameters passed to the web server. An attacker could exploit this vulnerability by convincing the user to
access a malicious link or by intercepting the user request and injecting the malicious code." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to execute arbitrary code in the
context of the affected site or allow the attacker to access sensitive browser-based information." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-16 11:06:29 +0700 (Fri, 16 Sep 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_cisco_ios_get_version.sc" );
	script_mandatory_keys( "cisco_ios/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version == "15.5(2)T"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

