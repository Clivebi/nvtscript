if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800069" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-5109" );
	script_name( "Adobe Flash Media Server Video Stream Capture Security Issue" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa08-11.html" );
	script_tag( name: "impact", value: "Successful attack could lead to capture and archive delivered video." );
	script_tag( name: "affected", value: "Adobe Flash Media Server 3.0.x prior to 3.0.3 and 3.5.x prior to 3.5.1 on Windows." );
	script_tag( name: "insight", value: "The security issue is that it is possible to establish RTMPE/RTMPTE sessions
  to Flash Media Server when SWF verification is not enabled." );
	script_tag( name: "solution", value: "Upgrade Adobe Flash Media Server version 3.0.3, 3.5.1 or later." );
	script_tag( name: "summary", value: "The host is running Adobe Flash Media Server (FMS), and is prone
  to a video streaming vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for entry in registry_enum_keys( key: key ) {
	fmsVer = registry_get_sz( key: key + entry, item: "DisplayName" );
	if(ContainsString( fmsVer, "Adobe Flash Media Server" )){
		fmsVer = eregmatch( pattern: "([0-9.]+)", string: fmsVer );
		if(!isnull( fmsVer[1] )){
			if(version_is_less( version: fmsVer[1], test_version: "3.0.3" ) || ( IsMatchRegexp( fmsVer[1], "^3\\.5" ) && version_is_less( version: fmsVer[1], test_version: "3.5.1" ) )){
				report = report_fixed_ver( installed_version: fmsVer[1], fixed_version: "3.0.3/3.5.1" );
				security_message( port: 0, data: report );
			}
		}
		exit( 0 );
	}
}
exit( 99 );

