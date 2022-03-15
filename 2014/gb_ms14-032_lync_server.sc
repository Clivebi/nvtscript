if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804459" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_bugtraq_id( 67893 );
	script_cve_id( "CVE-2014-1823" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-06-11 10:24:37 +0530 (Wed, 11 Jun 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft Lync Server Information Disclosure Vulnerability (2969258)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS14-032." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Certain unspecified input is not properly sanitised before being returned to
  the user. This can be exploited to execute arbitrary HTML and script code in
  a user's browser session in context of an affected site." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain sensitive
  information that may aid in further attacks." );
	script_tag( name: "affected", value: "Microsoft Lync Server 2013." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2963288" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms14-032" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "secpod_ms_lync_server_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Lync/Server/Name", "MS/Lync/Server/path" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
ms_lync_name = get_kb_item( "MS/Lync/Server/Name" );
if(ContainsString( ms_lync_name, "- Microsoft Lync Server 2013" )){
	ms_lync_path = get_kb_item( "MS/Lync/Server/path" );
	if(ms_lync_path){
		fname = "\\Web Components\\Autodiscover\\Ext\\Bin\\microsoft.rtc.internal.autodiscover.dll";
		dll_ver = fetch_file_version( sysPath: ms_lync_path, file_name: fname );
		if(dll_ver){
			if(version_in_range( version: dll_ver, test_version: "5.0", test_version2: "5.0.8308.419" )){
				report = report_fixed_ver( installed_version: dll_ver, vulnerable_range: "5.0 - 5.0.8308.419", install_path: ms_lync_path );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}

