CPE = "cpe:/a:cisco:prime_data_center_network_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105256" );
	script_bugtraq_id( 73479 );
	script_cve_id( "CVE-2015-0666" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_version( "$Revision: 12106 $" );
	script_name( "Cisco Data Center Network Manager Directory Traversal Vulnerability" );
	script_tag( name: "impact", value: "Exploiting this issue can allow an attacker to gain read access to
arbitrary files. Information harvested may aid in launching further attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "This issue is being tracked by Cisco Bug ID CSCus00241." );
	script_tag( name: "solution", value: "Update to 7.1(1) or higher." );
	script_tag( name: "summary", value: "Cisco Data Center Network Manager is prone to a directory-traversal
vulnerability." );
	script_tag( name: "affected", value: "Cisco Prime DCNM releases 6.3(1) and later, prior to release 7.1(1)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-04-14 14:19:43 +0200 (Tue, 14 Apr 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_prime_data_center_network_manager_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cisco_prime_dcnm/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	if(!vers = get_kb_item( "cisco_prime_dcnm/version" )){
		exit( 0 );
	}
}
rep_vers = vers;
vers = str_replace( string: vers, find: "(", replace: "." );
vers = str_replace( string: vers, find: ")", replace: "" );
if(version_in_range( version: vers, test_version: "6.3.1", test_version2: "7.1.0" )){
	report = "Installed Version: " + rep_vers + "\n" + "Fixed Version:     7.1(1)\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

