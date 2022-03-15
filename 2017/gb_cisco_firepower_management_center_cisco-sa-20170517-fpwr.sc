CPE = "cpe:/a:cisco:firepower_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106810" );
	script_cve_id( "CVE-2017-6632" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_name( "Cisco FirePOWER System Software SSL Logging Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-fpwr" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the logging configuration of Secure Sockets Layer (SSL)
  policies for Cisco FirePOWER System Software could allow an unauthenticated, remote attacker to cause a denial
  of service (DoS) condition due to high consumption of system resources." );
	script_tag( name: "insight", value: "The vulnerability is due to the logging of certain TCP packets by the
  affected software. An attacker could exploit this vulnerability by sending a flood of crafted TCP packets to an
  affected device." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to cause a DoS condition. The
  success of an exploit is dependent on how an administrator has configured logging for SSL policies for a device." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:28:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-18 09:11:02 +0700 (Thu, 18 May 2017)" );
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
affected = make_list( "5.3.0",
	 "5.4.0",
	 "6.0.0",
	 "6.0.1",
	 "6.0.1.3",
	 "6.1.0",
	 "6.1.0.2",
	 "6.2.0",
	 "6.2.1",
	 "6.2.2" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

