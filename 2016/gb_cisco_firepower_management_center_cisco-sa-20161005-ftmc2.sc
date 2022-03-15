CPE = "cpe:/a:cisco:firepower_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106335" );
	script_cve_id( "CVE-2016-6435" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "2020-04-03T09:54:35+0000" );
	script_name( "Cisco Firepower Management Center Console Local File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-ftmc2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web console of Cisco Firepower Management Center
  could allow an authenticated, remote attacker to access sensitive information." );
	script_tag( name: "insight", value: "The vulnerability is due to improper validation of parameters that are sent
  to the web console of an affected system. The vulnerability could allow an authenticated console user to access
  files that are readable by the www user on the server." );
	script_tag( name: "impact", value: "An attacker who has user privileges for the web console could leverage this
  vulnerability to read some of the files on the underlying operating system." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2020-04-03 09:54:35 +0000 (Fri, 03 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-10-06 11:16:38 +0700 (Thu, 06 Oct 2016)" );
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
if(version == "6.0.1"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

