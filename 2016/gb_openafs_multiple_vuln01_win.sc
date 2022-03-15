CPE = "cpe:/a:openafs:openafs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808076" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-6587", "CVE-2015-3282", "CVE-2015-3283" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-06-08 19:01:35 +0530 (Wed, 08 Jun 2016)" );
	script_name( "OpenAFS Multiple Vulnerabilities-01 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with OpenAFS and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An invalid validation of the regular expression in vlserver that allows
    pattern matching on volume names.

  - vos makes use of allocations for nvldbentry structures when updating
    VLDB entries which are not zeroed.

  - bos defaults to no encryption and clear connections." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to cause a denial of service or to obtain stack data by
  sniffing the network or to spoof bos commands." );
	script_tag( name: "affected", value: "OpenAFS version prior to 1.6.13 on Windows." );
	script_tag( name: "solution", value: "Update to OpenAFS version 1.6.13 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2015-001.txt" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2015-002.txt" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2015-006.txt" );
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
if(version_is_less( version: afsVer, test_version: "1.6.13" )){
	report = report_fixed_ver( installed_version: afsVer, fixed_version: "1.6.13" );
	security_message( data: report );
	exit( 0 );
}

