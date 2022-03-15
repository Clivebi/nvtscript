if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801631" );
	script_version( "2020-04-24T07:24:50+0000" );
	script_tag( name: "last_modification", value: "2020-04-24 07:24:50 +0000 (Fri, 24 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-11-12 15:34:28 +0100 (Fri, 12 Nov 2010)" );
	script_cve_id( "CVE-2010-4092" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Shockwave Player Use-After-Free Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42112" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_shockwave_player_detect.sc" );
	script_mandatory_keys( "Adobe/ShockwavePlayer/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the user-assisted remote
  attackers to execute arbitrary code via a crafted web site related to the
  Shockwave Settings window and an unloaded library." );
	script_tag( name: "affected", value: "Adobe Shockwave Player Version 11.5.9.615 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to a use-after-free error in an automatically
  installed compatibility component." );
	script_tag( name: "solution", value: "Upgrade to Adobe Shockwave Player Version 11.5.9.620." );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave Player and is prone
  to use-after-free vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
shockVer = get_kb_item( "Adobe/ShockwavePlayer/Ver" );
if(!shockVer){
	exit( 0 );
}
if(version_is_less_equal( version: shockVer, test_version: "11.5.9.615" )){
	report = report_fixed_ver( installed_version: shockVer, vulnerable_range: "Less or equal to 11.5.9.615" );
	security_message( port: 0, data: report );
}

