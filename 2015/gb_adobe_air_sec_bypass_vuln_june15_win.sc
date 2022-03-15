CPE = "cpe:/a:adobe:adobe_air";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805590" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-3097" );
	script_bugtraq_id( 75090 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-06-15 13:30:22 +0530 (Mon, 15 Jun 2015)" );
	script_name( "Adobe Air Security Bypass Vulnerability - June15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Air and
  and is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The error exists due to improper selection
  of a random memory address for the Flash heap." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions and execute arbitrary code on
  affected system." );
	script_tag( name: "affected", value: "Adobe Air versions before 18.0.0.180 on
  Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Air version 18.0.0.180
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb15-16.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_reg.inc.sc");
if(hotfix_check_sp( win7x64: 2 ) <= 0){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "18.0.0.180" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + "18.0.0.180" + "\n";
	security_message( data: report );
	exit( 0 );
}

