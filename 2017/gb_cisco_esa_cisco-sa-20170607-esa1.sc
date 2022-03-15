CPE = "cpe:/h:cisco:email_security_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106855" );
	script_cve_id( "CVE-2017-6671" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_name( "Cisco Email Security Appliance Attachment Filter Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-esa1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the email message scanning of Cisco AsyncOS Software for
Cisco Email Security Appliance (ESA) could allow an unauthenticated, remote attacker to bypass configured filters
on the device." );
	script_tag( name: "insight", value: "The vulnerability is due to improper input validation of an email with an
attachment and modified Multipurpose Internet Mail Extensions (MIME) header. An attacker could exploit this
vulnerability by sending a malformed email message with an attachment." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to bypass configured message
filters to drop the email. The email may not be RFC compliant. However, some mail clients could still allow users
to read the email, which may not have been properly filtered by the device." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-27 12:15:00 +0000 (Mon, 27 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-06-08 11:08:56 +0700 (Thu, 08 Jun 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_esa_version.sc" );
	script_mandatory_keys( "cisco_esa/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "9.7.1-066",
	 "10.0.1-087" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

