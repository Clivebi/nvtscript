CPE = "cpe:/a:cisco:firepower_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105774" );
	script_cve_id( "CVE-2016-1431" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2020-04-03T09:54:35+0000" );
	script_name( "Cisco Firepower Management Center Persistent Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160617-fmc" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the HTTP framework of Cisco Firepower Management Center
  could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against an
  affected device.

  The vulnerability is due to insufficient filtering of output data. An attacker could exploit this
  vulnerability by persuading a user to follow a link to a malicious site or by intercepting a user
  request and injecting malicious code into the request. A successful exploit could allow the attacker
  to execute arbitrary script in the context of the site or access sensitive browser-based information.

  Cisco has not released software updates that address this vulnerability. There are no workarounds
  that address this vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2020-04-03 09:54:35 +0000 (Fri, 03 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-06-20 12:52:45 +0200 (Mon, 20 Jun 2016)" );
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
affected = make_list( "5.3.0",
	 "5.3.1",
	 "5.4.0",
	 "5.2.0",
	 "4.10.3" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );
