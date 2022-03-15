CPE = "cpe:/h:cisco:email_security_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106594" );
	script_cve_id( "CVE-2017-3827" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_name( "Cisco AsyncOS Software for Cisco ESA Filtering Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-asyncos" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Multipurpose Internet Mail Extensions (MIME) scanner
of Cisco AsyncOS Software for Cisco Email Security Appliances (ESA) could allow an unauthenticated, remote
attacker to bypass configured user filters on the device." );
	script_tag( name: "insight", value: "The vulnerability is due to improper error handling of a malformed MIME
header in an email attachment. An attacker could exploit this vulnerability by sending an email with a crafted
MIME attachment." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to bypass user filters
configured to prevent executable files from being opened. The malformed MIME headers may not be RFC compliant but
some mail clients could still allow users to access the attachment, which may not have been properly filtered by
the device." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-25 01:29:00 +0000 (Tue, 25 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-02-16 11:47:47 +0700 (Thu, 16 Feb 2017)" );
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
affected = make_list( "10.0.0-082",
	 "10.0.0-124",
	 "10.0.0-125",
	 "10.0.0-203",
	 "10.0.0-232",
	 "9.9.6-026",
	 "9.9.9-894" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

