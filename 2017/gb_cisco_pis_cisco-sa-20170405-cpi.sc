CPE = "cpe:/a:cisco:prime_infrastructure";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106735" );
	script_cve_id( "CVE-2017-3884" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_name( "Cisco Prime Infrastructure Web Interface Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cpi" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web interface of Cisco Prime Infrastructure could
allow an authenticated, remote attacker to access sensitive data. The attacker does not need administrator
credentials and could use this information to conduct additional reconnaissance attacks." );
	script_tag( name: "insight", value: "The vulnerability occurs because the application does not sufficiently
protect sensitive data when responding to an HTTP request to the web interface. An attacker could exploit the
vulnerability by sending a crafted HTTP request to the targeted application." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to obtain sensitive information about the
application." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-29 17:46:00 +0000 (Mon, 29 Jul 2019)" );
	script_tag( name: "creation_date", value: "2017-04-10 10:49:04 +0200 (Mon, 10 Apr 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_pis_version.sc" );
	script_mandatory_keys( "cisco_pis/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "2.2.0",
	 "2.2.3",
	 "3.0.0",
	 "3.1.0",
	 "3.1.0.128",
	 "3.1.4.0",
	 "3.1.5.0",
	 "3.2.0.0" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

