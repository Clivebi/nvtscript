CPE = "cpe:/a:siemens:simatic_s7_300";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106100" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-06-20 09:41:29 +0700 (Mon, 20 Jun 2016)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2016-3949" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Siemens SIMATIC S7-300 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_simatic_s7_version.sc" );
	script_mandatory_keys( "simatic_s7/detected" );
	script_tag( name: "summary", value: "Siemens SIMATIC S7-300 is prone to a denial of service
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An exploit of this vulnerability could cause the affected device
  to go into defect mode, requiring a cold restart to recover the system." );
	script_tag( name: "impact", value: "A remote attacker may cause a DoS condition." );
	script_tag( name: "affected", value: "Version prior to 3.3.12." );
	script_tag( name: "solution", value: "Upgrade to version 3.3.12 or later." );
	script_xref( name: "URL", value: "https://www.siemens.com/cert/pool/cert/siemens_security_advisory_ssa-818183.pdf" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-16-161-01" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "3.3.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.12" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

