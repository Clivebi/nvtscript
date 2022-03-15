CPE = "cpe:/a:hp:data_protector";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103975" );
	script_version( "2021-08-09T06:49:35+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 06:49:35 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-02-11 11:34:29 +0700 (Tue, 11 Feb 2014)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2013-6194" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP (OpenView Storage) Data Protector Backup Client Service Directory Traversal" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "hp_data_protector_installed.sc" );
	script_mandatory_keys( "microfocus/data_protector/detected" );
	script_tag( name: "impact", value: "A remote attacker can upload and execute abitrary code." );
	script_tag( name: "affected", value: "HP (OpenView Storage) Data Protector 6.21 and prior." );
	script_tag( name: "insight", value: "There is a directory traversal vulnerability in HP
  (OpenView Storage) Data Protector. The vulnerability is in the backup client service when parsing
  packets with opcode 42." );
	script_tag( name: "summary", value: "HP (OpenView Storage) Data Protector is prone to a directory
  traversal vulnerability which might lead to execution of arbitrary code." );
	script_tag( name: "solution", value: "Apply the patch from the referenced link or update to a newer
  version." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03822422" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/31181/" );
	script_xref( name: "URL", value: "https://ovrd.external.hp.com/hpp/hpp2rd" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "06.21" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "06.22" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

