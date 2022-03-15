CPE = "cpe:/a:microsoft:exchange_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815516" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_cve_id( "CVE-2019-1136", "CVE-2019-1084" );
	script_bugtraq_id( 109030, 108929 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-10 09:35:44 +0530 (Wed, 10 Jul 2019)" );
	script_name( "Microsoft Exchange Server Multiple Vulnerabilities (KB4509410)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4509410." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error when Exchange allows creation of entities with Display Names having
    non-printable characters.

  - An elevation of privilege error in Microsoft Exchange Server." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain the same rights as any other user of the Exchange server and gain access
  to potentially sensitive information." );
	script_tag( name: "affected", value: "Microsoft Exchange Server 2010 Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4509410" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_exchange_server_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Exchange/Server/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
exchangePath = get_app_location( cpe: CPE, skip_port: TRUE );
if(!exchangePath || ContainsString( exchangePath, "Could not find the install location" )){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: exchangePath, file_name: "Bin\\ExSetup.exe" );
if(!exeVer){
	exit( 0 );
}
if(IsMatchRegexp( exeVer, "^14\\." ) && version_is_less( version: exeVer, test_version: "14.3.468" )){
	report = report_fixed_ver( file_checked: exchangePath + "Bin\\ExSetup.exe", file_version: exeVer, vulnerable_range: "14.0 - 14.3.467" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

