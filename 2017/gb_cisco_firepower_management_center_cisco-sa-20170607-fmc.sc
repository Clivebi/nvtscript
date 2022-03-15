CPE = "cpe:/a:cisco:firepower_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106856" );
	script_cve_id( "CVE-2017-6673" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_name( "Cisco Firepower Management Center Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-fmc" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 6.2.0 or later." );
	script_tag( name: "summary", value: "A vulnerability in Cisco Firepower Management Center could allow an
  authenticated, remote attacker to obtain user information. An attacker could use this information to perform
  reconnaissance." );
	script_tag( name: "insight", value: "The vulnerability is due to verbose output in HTTP log files." );
	script_tag( name: "impact", value: "An attacker could retrieve the log files from an affected system and use the
  information to conduct further attacks." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-20 14:53:00 +0000 (Tue, 20 Jun 2017)" );
	script_tag( name: "creation_date", value: "2017-06-08 11:24:24 +0700 (Thu, 08 Jun 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_firepower_management_center_consolidation.sc" );
	script_mandatory_keys( "cisco/firepower_management_center/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
affected = make_list( "6.1.0.2",
	 "6.1.0" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.2.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

