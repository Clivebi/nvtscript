CPE = "cpe:/a:mcafee:total_protection";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807237" );
	script_version( "$Revision: 12051 $" );
	script_cve_id( "CVE-2015-8772", "CVE-2015-8773" );
	script_bugtraq_id( 82143, 82144 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-02-08 17:22:31 +0530 (Mon, 08 Feb 2016)" );
	script_name( "McAfee Total Protection Multiple Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with McAfee Total
  Protection and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The McAfee File Lock Driver does not handle correctly IOCTL_DISK_VERIFY
    IOCTL requests.

  - The McAfee File Lock Driver does not handle correctly GUIDs of the encrypted
    vaults." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to disclose sensitive information from kernel memory or crash the affected host." );
	script_tag( name: "affected", value: "McAfee Total Protection kernel driver
  module 'McPvDrv.sys' version 4.6.111.0 and probably earlier." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.nettitude.co.uk/mcafee-file-lock-driver-kernel-memory-leak" );
	script_xref( name: "URL", value: "https://www.nettitude.co.uk/mcafee-file-lock-driver-kernel-stack-based-bof" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mcafee_total_protection_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "McAfee/TotalProtection/Win/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Drivers\\McPvDrv.sys" );
if(!sysVer){
	exit( 0 );
}
if(version_is_less_equal( version: sysVer, test_version: "4.6.111.0" )){
	report = report_fixed_ver( installed_version: sysVer, fixed_version: "None Available" );
	security_message( data: report );
	exit( 0 );
}

