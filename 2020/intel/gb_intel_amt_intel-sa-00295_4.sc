CPE = "cpe:/h:intel:active_management_technology";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144120" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-17 04:51:40 +0000 (Wed, 17 Jun 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-18 13:15:00 +0000 (Thu, 18 Mar 2021)" );
	script_cve_id( "CVE-2020-0597", "CVE-2020-11899" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Intel Active Management Technology DoS Vulnerability (INTEL-SA-00295)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_intel_amt_webui_detect.sc" );
	script_mandatory_keys( "intel_amt/installed" );
	script_tag( name: "summary", value: "Intel Active Management Technology (AMT) is prone to a denial of service
  vulnerability." );
	script_tag( name: "insight", value: "Out-of-bounds read in IPv6 subsystem in Intel(R) AMT may allow an
  unauthenticated user to potentially enable denial of service via network access.

  Note: CVE-2020-0597 as assigned by Intel correspond to a subset of the CVEs disclosed in the linked
  'Treck IP stacks contain multiple vulnerabilities' advisory (covering the 'Ripple20' called vulnerabilities)
  and is matching CVE-2020-11899." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Intel Active Management Technology version 14.0.32." );
	script_tag( name: "solution", value: "Upgrade to version 14.0.33 or later." );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00295.html" );
	script_xref( name: "URL", value: "https://kb.cert.org/vuls/id/257161" );
	script_xref( name: "URL", value: "https://treck.com/vulnerability-response-information/" );
	script_xref( name: "URL", value: "https://www.jsof-tech.com/ripple20/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version == "14.0.32"){
	report = report_fixed_ver( installed_version: version, fixed_version: "14.0.33", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

