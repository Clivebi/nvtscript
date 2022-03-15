CPE = "cpe:/a:cisco:firepower_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106185" );
	script_cve_id( "CVE-2016-1457" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_version( "2020-04-03T09:54:35+0000" );
	script_name( "Cisco Firepower Management Center Remote Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-fmc" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web-based GUI of Cisco Firepower Management
  Center and Cisco Adaptive Security Appliance (ASA) 5500-X Series with FirePOWER Services could allow an
  authenticated, remote attacker to perform unauthorized remote command execution on the affected device.

  The vulnerability is due to insufficient authorization checking. An attacker could exploit this
  vulnerability by sending crafted HTTP requests to the affected device. Successful exploitation could
  allow an authenticated attacker to execute system commands with root-level privileges.

  Cisco has released software updates that address this vulnerability. Workarounds that address this
  vulnerability are not available." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2020-04-03 09:54:35 +0000 (Fri, 03 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-08-18 14:37:41 +0700 (Thu, 18 Aug 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_firepower_management_center_consolidation.sc" );
	script_mandatory_keys( "cisco/firepower_management_center/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
affected = make_list( "4.10.3.9",
	 "5.2.0",
	 "5.3.0.4",
	 "5.3.1",
	 "5.4.0" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

