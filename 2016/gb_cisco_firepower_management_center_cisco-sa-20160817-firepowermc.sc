CPE = "cpe:/a:cisco:firepower_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106186" );
	script_cve_id( "CVE-2016-6365" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2020-04-03T09:54:35+0000" );
	script_name( "Cisco Firepower Management Center Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-firepowermc" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web framework of Cisco Firepower Management
  Center could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against
  a user of the web interface of an affected system.

  The vulnerability is due to insufficient input validation for some of the parameters that are passed
  to an affected web server. An attacker could exploit this vulnerability by persuading a user to
  access a malicious link or by intercepting a user request and injecting malicious code into the
  request. A successful exploit could allow the attacker to execute arbitrary script code in the
  context of the affected site or allow the attacker to access sensitive browser-based information.

  Cisco has released software updates that address this vulnerability. There are no workarounds that
  address this vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2020-04-03 09:54:35 +0000 (Fri, 03 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-08-18 14:46:53 +0700 (Thu, 18 Aug 2016)" );
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
affected = make_list( "4.10.3",
	 "5.2.0",
	 "5.3.0",
	 "5.3.0.2",
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

