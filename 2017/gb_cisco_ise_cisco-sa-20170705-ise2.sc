CPE = "cpe:/a:cisco:identity_services_engine";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106925" );
	script_cve_id( "CVE-2017-6734" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_name( "Cisco Identity Services Engine Guest Portal Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170705-ise2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web-based management interface of Cisco Identity
Services Engine (ISE) Software could allow an authenticated, remote attacker to conduct a cross-site scripting
(XSS) attack against a user of the web interface of an affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient validation of user-supplied input
by the web-based management interface of the affected software. An attacker could exploit this vulnerability by
persuading a user of the interface to click a crafted link." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to execute arbitrary script
code in the context of the interface or allow the attacker to access sensitive browser-based information." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-14 13:43:00 +0000 (Fri, 14 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-07-06 10:41:12 +0700 (Thu, 06 Jul 2017)" );
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
affected = make_list( "1.3.0.722",
	 "1.3.0.876",
	 "1.3.0.909",
	 "1.3.106.146",
	 "1.3.120.135",
	 "2.1.0.474",
	 "2.1.0.800",
	 "2.1.102.101" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

