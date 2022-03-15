CPE = "cpe:/a:openafs:openafs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808074" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-4536", "CVE-2016-2860" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-06-08 17:01:13 +0530 (Wed, 08 Jun 2016)" );
	script_name( "OpenAFS Multiple Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with OpenAFS and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An improper validation in the newEntry function in 'ptserver/ptprocs.c'
    script.

  - The client does not properly initialize the AFSStoreStatus,
    AFSStoreVolumeStatus, VldbListByAttributes, and ListAddrByAttributes
    structures." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to obtain sensitive memory information by leveraging
  access to RPC call traffic and bypass intended access restrictions and
  create arbitrary groups as administrators by leveraging mishandling of
  the creator ID." );
	script_tag( name: "affected", value: "OpenAFS version prior and equal to 1.6.16
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to OpenAFS version 1.6.17 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2016-001.txt" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2016-002.txt" );
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
if(version_is_less_equal( version: afsVer, test_version: "1.6.16" )){
	report = report_fixed_ver( installed_version: afsVer, fixed_version: "1.6.17" );
	security_message( data: report );
	exit( 0 );
}

