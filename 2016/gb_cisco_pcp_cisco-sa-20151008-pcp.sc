CPE = "cpe:/a:cisco:prime_collaboration_provisioning";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105739" );
	script_bugtraq_id( 77050 );
	script_cve_id( "CVE-2015-6329" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_version( "$Revision: 13999 $" );
	script_name( "Cisco Prime Collaboration Provisioning SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/77050" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151008-pcp" );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by sending a crafted SQL statement to an affected system.
  Successful exploitation could allow the attacker to read, modify, or delete entries in some database tables." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to a failure to validate user-supplied input used in SQL queries." );
	script_tag( name: "solution", value: "Update to 11.0.0.582 or later." );
	script_tag( name: "summary", value: "A vulnerability in web framework of Cisco Prime Collaboration Provisioning (PCP) could allow an authenticated,
  remote attacker to execute unauthorized SQL queries." );
	script_tag( name: "affected", value: "Cisco Prime Collaboration Provisioning versions 10.6 and 11.0 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-05 14:15:01 +0100 (Tue, 05 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-30 15:41:14 +0200 (Mon, 30 May 2016)" );
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
if(IsMatchRegexp( vers, "^(10\\.6|11\\.0)" )){
	if(version_is_less( version: vers, test_version: "11.0.0.582" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "11.0.0.582" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

