CPE = "cpe:/a:novell:iprint";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801423" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)" );
	script_cve_id( "CVE-2010-3109", "CVE-2010-3108", "CVE-2010-3107", "CVE-2010-3106" );
	script_bugtraq_id( 42100 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Novell iPrint Client Multiple Security Vulnerabilities (Windows)" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_novell_prdts_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "Novell/iPrint/Installed" );
	script_xref( name: "URL", value: "http://dvlabs.tippingpoint.com/advisory/TPTI-10-06" );
	script_xref( name: "URL", value: "http://dvlabs.tippingpoint.com/advisory/TPTI-10-05" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-10-139/" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-10-140/" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code,
  delete files on a system." );
	script_tag( name: "affected", value: "Novell iPrint Client version 5.40 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Error in handling 'ienipp.ocx' ActiveX control.

  - Error within the nipplib.dll module that can be reached via the 'ienipp.ocx'
    ActiveX control with 'CLSID 36723f97-7aa0-11d4-8919-FF2D71D0D32C'.

  - Failure to verify the name of parameters passed via '<embed>' tags.

  - Error in handling plugin parameters. A long value for the operation
    parameter can trigger a stack-based buffer overflow." );
	script_tag( name: "summary", value: "The host is installed with Novell iPrint Client and is prone to
  multiple vulnerabilities." );
	script_tag( name: "solution", value: "Update to version 5.42 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_activex.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
iPrintVer = infos["version"];
if(version_is_less_equal( version: iPrintVer, test_version: "5.40" )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
	if(!path){
		exit( 0 );
	}
	path = path + "\\ienipp.ocx";
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: path );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: path );
	ocxSize = get_file_size( share: share, file: file );
	if(ocxSize){
		killbit = "{36723f97-7aa0-11d4-8919-FF2D71D0D32C}";
		if(is_killbit_set( clsid: killbit ) == 0){
			report = report_fixed_ver( installed_version: iPrintVer, vulnerable_range: "Less than or equal to 5.40", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}

