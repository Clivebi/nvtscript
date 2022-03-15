CPE = "cpe:/a:openafs:openafs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808077" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2015-3285" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-06-08 19:35:27 +0530 (Wed, 08 Jun 2016)" );
	script_name( "OpenAFS Denial of Service Vulnerability-01 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with OpenAFS and
  is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the kernel handling
  of the FS command for OSD uses a pointer to the wrong in-kernel memory
  when returning the result of the RPC." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  users to cause a denial of service (memory corruption and kernel panic) via
  a crafted OSD FS command." );
	script_tag( name: "affected", value: "OpenAFS version 1.0.3 through 1.6.12
  on Windows." );
	script_tag( name: "solution", value: "Update to OpenAFS version 1.6.13 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2015-004.txt" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
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
if(version_in_range( version: afsVer, test_version: "1.0.3", test_version2: "1.6.12" )){
	report = report_fixed_ver( installed_version: afsVer, fixed_version: "1.6.13" );
	security_message( data: report );
	exit( 0 );
}

