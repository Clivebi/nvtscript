CPE = "cpe:/a:cisco:identity_services_engine";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106926" );
	script_cve_id( "CVE-2017-6733" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_name( "Cisco Identity Services Engine Stored Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170705-ise1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web-based application interface of the Cisco Identity
Services Engine (ISE) portal could allow an unauthenticated, remote attacker to conduct a stored cross-site
scripting (XSS) attack against a user of the web interface of an affected system." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation and output-encoding
parameters for data that is passed between an affected client and server. An attacker could exploit this
vulnerability by intercepting targeted user packets and injecting malicious code into the targeted traffic
stream." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to inject script code into the
HTTP flow between the targeted user and the affected system." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-16 11:32:00 +0000 (Sun, 16 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-07-06 10:48:11 +0700 (Thu, 06 Jul 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ise_version.sc" );
	script_mandatory_keys( "cisco_ise/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "2.1.0.474",
	 "2.1.0.800",
	 "2.1.102.101",
	 "2.2.0.283" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

