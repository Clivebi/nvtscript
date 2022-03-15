CPE = "cpe:/a:cisco:ip_interoperability_and_collaboration_system";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105603" );
	script_cve_id( "CVE-2016-1375" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 14181 $" );
	script_name( "Cisco IP Interoperability and Collaboration System Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160407-cic" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy12339" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy12340" );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by persuading a user of an
  affected system to follow a malicious link." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient XSS protections." );
	script_tag( name: "solution", value: "Update to version 5.0(1) or later. Please see the references for more information." );
	script_tag( name: "summary", value: "A vulnerability in the web framework code of Cisco IP Interoperability and Collaboration
  System could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-11 14:05:33 +0200 (Mon, 11 Apr 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ipics_version.sc" );
	script_mandatory_keys( "cisco/ipics/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version == "4.10(1)"){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0(1)" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

