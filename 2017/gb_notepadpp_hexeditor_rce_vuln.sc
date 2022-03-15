CPE = "cpe:/a:don_ho:notepad++";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811586" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2017-8803" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-13 11:26:00 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-22 14:00:19 +0530 (Tue, 22 Aug 2017)" );
	script_name( "Notepad++ Hex Editor Plugin Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_notepadpp_detect_portable_win.sc" );
	script_mandatory_keys( "Notepad++32/Win/installed" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-8803" );
	script_tag( name: "summary", value: "The host is installed with Notepad++
  and is prone to a Buffer Overflow Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version of Notepad++ and the Hex Editor Plugin
  is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a 'Data from Faulting
  Address controls Code Flow' issue in Hex Editor in Notepad++." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  user-assisted attackers to execute code via a crafted file." );
	script_tag( name: "affected", value: "Notepad++ version 7.3.3 (32-bit) with
  Hex Editor Plugin v0.9.5 on Windows." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(vers != "7.3.3" || !path || ContainsString( path, "Could not find the install location from registry" )){
	exit( 0 );
}
if(!dllVer = fetch_file_version( sysPath: path, file_name: "plugins\\hexeditor.dll" )){
	exit( 0 );
}
if(dllVer == "0.9.5.0"){
	report = report_fixed_ver( installed_version: "Notepad++ version " + vers + ", Hex Editor version" + dllVer, fixed_version: "NoneAvailable", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

