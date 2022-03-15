CPE = "cpe:/a:adobe:shockwave_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806520" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-7649" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-10-29 18:35:04 +0530 (Thu, 29 Oct 2015)" );
	script_name( "Adobe Shockwave Player Denial of Service Vulnerability Oct15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave
  Player and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a memory corruption
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service." );
	script_tag( name: "affected", value: "Adobe Shockwave Player version before
  12.2.1.171 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Shockwave Player version
  12.2.0.171 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/shockwave/apsb15-26.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_adobe_shockwave_player_detect.sc" );
	script_mandatory_keys( "Adobe/ShockwavePlayer/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "12.2.1.171" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + "12.2.1.171" + "\n";
	security_message( data: report );
	exit( 0 );
}

