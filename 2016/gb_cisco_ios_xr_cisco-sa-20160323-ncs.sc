CPE = "cpe:/o:cisco:ios_xr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105647" );
	script_cve_id( "CVE-2016-1366" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:C/A:N" );
	script_version( "$Revision: 12363 $" );
	script_name( "Cisco IOS XR Software SCP and SFTP Modules Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ncs" );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by using either the SCP or SFTP client to overwrite system files on the affected device. An exploit could allow the attacker to overwrite system files and cause a DoS condition." );
	script_tag( name: "vuldetect", value: "Check the IOS XR Version" );
	script_tag( name: "insight", value: "The vulnerability is due to improper setting of permissions on the filesystem for certain paths that include system files." );
	script_tag( name: "solution", value: "See the referenced advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Secure Copy Protocol (SCP) and Secure FTP (SFTP) modules of Cisco IOS XR Software could allow an authenticated, remote attacker to overwrite system files and cause a denial of service (DoS) condition." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-05-04 17:40:08 +0200 (Wed, 04 May 2016)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xr_version.sc" );
	script_mandatory_keys( "cisco/ios_xr/version", "cisco/ios_xr/model" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!model = get_kb_item( "cisco/ios_xr/model" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "5.2.1",
	 "5.2.4",
	 "5.2.3",
	 "5.2.5",
	 "5.0.0",
	 "5.0.1" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See vendor advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

