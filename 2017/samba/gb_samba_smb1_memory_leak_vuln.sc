CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811905" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-12163" );
	script_bugtraq_id( 100925 );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-09-22 13:09:22 +0530 (Fri, 22 Sep 2017)" );
	script_name( "Samba Server 'SMB1' Memory Information Leak Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc", "gb_smb_version_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2017-12163.html" );
	script_tag( name: "summary", value: "Samba is prone to a memory information leak vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A server memory information leak bug over SMB1
  if a client can write data to a share. Some SMB1 write requests were not correctly
  range checked to ensure the client had sent enough data to fulfill the write." );
	script_tag( name: "impact", value: "Successful exploitation will allow a client with
  write access to a share can cause server memory contents to be written into a file
  or printer." );
	script_tag( name: "affected", value: "Samba versions before 4.4.16,
  4.5.0 before 4.5.14, and 4.6.0 before 4.6.8." );
	script_tag( name: "solution", value: "Upgrade to Samba 4.6.8, 4.5.14 and 4.4.16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
loc = infos["location"];
if(!get_kb_item( "smb_v1/supported" )){
	exit( 0 );
}
if( version_is_less( version: vers, test_version: "4.4.16" ) ){
	fix = "4.4.16";
}
else {
	if( version_in_range( version: vers, test_version: "4.5.0", test_version2: "4.5.13" ) ){
		fix = "4.5.14";
	}
	else {
		if(version_in_range( version: vers, test_version: "4.6.0", test_version2: "4.6.7" )){
			fix = "4.6.8";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: loc );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

