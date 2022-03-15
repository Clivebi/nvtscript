CPE = "cpe:/a:cisco:intercloud_fabric";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106487" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-23 10:52:32 +0700 (Fri, 23 Dec 2016)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-29 14:41:00 +0000 (Thu, 29 Dec 2016)" );
	script_cve_id( "CVE-2016-9217" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Intercloud Fabric Database Static Credentials Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_intercloud_fabric_detect.sc" );
	script_mandatory_keys( "cisco/intercloud_fabric/version" );
	script_tag( name: "summary", value: "A vulnerability in Cisco Intercloud Fabric for Business and Cisco
  Intercloud Fabric for Providers could allow an unauthenticated, remote attacker to connect to the database used
  by these products." );
	script_tag( name: "insight", value: "The vulnerability occurs because the database account uses static
  credentials.

  Note that this database contains only internal objects used by the application. The database does not contain
  other credentials.

  Please note that this product has entered the end-of-sale and end-of-life process." );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by using these credentials to
  connect to the database. The contents of the database can then be examined or modified." );
	script_tag( name: "affected", value: "Cisco Cisco Intercloud Fabric 2.2.1, 2.3.1 and 3.1.1." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161221-icf" );
	script_xref( name: "URL", value: "http://www.cisco.com/c/en/us/products/collateral/cloud-systems-management/intercloud-fabric/eos-eol-notice-c51-738014.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "3.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

