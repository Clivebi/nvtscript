CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105467" );
	script_cve_id( "CVE-2015-6376" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 12106 $" );
	script_name( "Cisco TelePresence Video Communication Server Cross-Site Request Forgery Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151120-tvcs" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to a lack of cross-site request forgery (CSRF) protections. An attacker could exploit this vulnerability by persuading a user of the web application to execute an adverse action." );
	script_tag( name: "solution", value: "See vendor advisory" );
	script_tag( name: "summary", value: "A vulnerability in Cisco TelePresence Video Communication Server (VCS) could allow an unauthenticated, remote attacker to execute unwanted actions." );
	script_tag( name: "affected", value: "Cisco TelePresence Video Communication Server (VCS) version X8.5.1 is vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-26 13:00:05 +0100 (Thu, 26 Nov 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_vcs_detect.sc", "gb_cisco_vcs_ssh_detect.sc" );
	script_mandatory_keys( "cisco_vcs/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^8\\.5\\.1($|[^0-9])" )){
	report = "Installed version: " + version + "\n" + "Fixed version:     Ask the vendor\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );
