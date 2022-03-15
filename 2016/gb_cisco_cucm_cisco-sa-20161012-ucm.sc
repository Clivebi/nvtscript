CPE = "cpe:/a:cisco:unified_communications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107061" );
	script_cve_id( "CVE-2016-6440" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 14181 $" );
	script_name( "Cisco Unified Communications Manager iFrame Data Clickjacking Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161012-ucm" );
	script_tag( name: "impact", value: "An exploit could allow the attacker to perform a clickjacking or phishing attack where the user is
  tricked into clicking on a malicious link. Protection mechanisms should be used to prevent this type of attack." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to a lack of proper input sanitization of iframe data within the HTTP requests
  sent to the device. An attacker could exploit this vulnerability by sending crafted HTTP packets with malicious iframe data." );
	script_tag( name: "solution", value: "Updates are available. Please see the vendor advisory for more information." );
	script_tag( name: "summary", value: "could allow the attacker to perform a clickjacking or phishing attack where the user is tricked into clicking on a malicious link." );
	script_tag( name: "affected", value: "Cisco Unified Communications Manager 11.0(1.10000.10), 11.5(1.10000.6) and 11.5(0.99838.4) are affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-10-14 14:48:29 +0100 (Fri, 14 Oct 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_cucm_version.sc" );
	script_mandatory_keys( "cisco/cucm/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
vers = str_replace( string: vers, find: "-", replace: "." );
if(( vers == "11.0.1.10000.10" ) || ( vers == "11.5.1.10000.6" ) || ( vers == "11.5.0.99838.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See vendor advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

