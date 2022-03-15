if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106157" );
	script_version( "2020-06-08T14:13:59+0000" );
	script_tag( name: "last_modification", value: "2020-06-08 14:13:59 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-07-29 09:30:37 +0700 (Fri, 29 Jul 2016)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_cve_id( "CVE-2015-8675" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei S5300 Campus Series Switches information Disclosure Vulnerability (huawei-sa-20160112-01-switch)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Huawei S5300 Campus Series switches are prone to a local information
  disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "When uploading files to some directory, the user needs to enter the
  username and password. However, the system does not mask passwords. As a result, the password entered is
  displayed in plain text, leading to password leaks." );
	script_tag( name: "impact", value: "Physically proximate attackers may obtain sensitive password information
  by reading the display." );
	script_tag( name: "affected", value: "Versions prior to V200R005SPH008." );
	script_tag( name: "solution", value: "Upgrade to Version V200R005SPH008 or later." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20160112-01-switch-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("revisions-lib.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:s5300_firmware" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
if(!version = get_app_version( cpe: cpe, nofork: TRUE )){
	exit( 0 );
}
version = toupper( version );
if(revcomp( a: version, b: "V200R005SPH008" ) < 0){
	report = report_fixed_ver( installed_version: version, fixed_version: "V200R005SPH008" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

