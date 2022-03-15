CPE = "cpe:/a:openafs:openafs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808075" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2015-8312" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-17 16:09:00 +0000 (Thu, 17 May 2018)" );
	script_tag( name: "creation_date", value: "2016-06-08 17:54:13 +0530 (Wed, 08 Jun 2016)" );
	script_name( "OpenAFS Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with OpenAFS and
  is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an Off-by-one error
  in 'afs_pioctl.c' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  users to cause a denial of service (memory overwrite and system crash) via a
  pioctl with an input buffer size of 4096 bytes." );
	script_tag( name: "affected", value: "OpenAFS version prior to 1.6.16 on Windows." );
	script_tag( name: "solution", value: "Update to OpenAFS version 1.6.16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.openafs.org/dl/1.6.16/RELNOTES-1.6.16" );
	script_xref( name: "URL", value: "http://git.openafs.org/?p=openafs.git;a=commitdiff;h=2ef863720da4d9f368aaca0461c672a3008195ca" );
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
if(version_is_less( version: afsVer, test_version: "1.6.16" )){
	report = report_fixed_ver( installed_version: afsVer, fixed_version: "1.6.16" );
	security_message( data: report );
	exit( 0 );
}

