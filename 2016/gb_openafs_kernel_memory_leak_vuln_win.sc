CPE = "cpe:/a:openafs:openafs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808078" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-3284" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-06-08 19:45:07 +0530 (Wed, 08 Jun 2016)" );
	script_name( "OpenAFS Kernel Memory Leak Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with OpenAFS and
  is prone to kernel memory leak vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper handling
  of kernel's pioctl calls ." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  users to read kernel memory via crafted commands." );
	script_tag( name: "affected", value: "OpenAFS version 1.6.0 through 1.6.12
  on Windows." );
	script_tag( name: "solution", value: "Update to OpenAFS version 1.6.13 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2015-003.txt" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_openafs_detect.sc" );
	script_mandatory_keys( "OpenAFS/Win/Installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!afsVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: afsVer, test_version: "1.6.0", test_version2: "1.6.12" )){
	report = report_fixed_ver( installed_version: afsVer, fixed_version: "1.6.13" );
	security_message( data: report );
	exit( 0 );
}

