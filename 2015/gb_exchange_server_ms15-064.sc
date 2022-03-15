CPE = "cpe:/a:microsoft:exchange_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805198" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-1764", "CVE-2015-1771", "CVE-2015-2359" );
	script_bugtraq_id( 75007, 75011, 75013 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-06-10 10:26:35 +0530 (Wed, 10 Jun 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Exchange Server Privilege Escalation Vulnerability (3062157)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-064." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to Microsoft Exchange web
  applications when Exchange does not properly manage same-origin policy." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to scan and attack systems behind a firewall that are normally
  inaccessible from the outside world, enumerate and attack services that are
  running on these host systems and exploit host-based authentication services." );
	script_tag( name: "affected", value: "Microsoft Exchange Server 2013 SP1 and Microsoft Exchange Server 2013 Cumulative Update 8." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3062157" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-064" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.847.40" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

