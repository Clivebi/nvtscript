CPE = "cpe:/a:adobe:shockwave_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805980" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-6680", "CVE-2015-6681" );
	script_bugtraq_id( 76664 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-09-14 10:49:07 +0530 (Mon, 14 Sep 2015)" );
	script_name( "Adobe Shockwave Player Multiple Vulnerabilities -01 Sep15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave
  Player and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple memory
  corruption errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack and potentially execute arbitrary
  code in the context of the affected user." );
	script_tag( name: "affected", value: "Adobe Shockwave Player version before
  12.2.0.162 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Shockwave Player version
  12.2.0.162 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/shockwave/apsb15-22.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_shockwave_player_detect.sc" );
	script_mandatory_keys( "Adobe/ShockwavePlayer/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "12.2.0.162" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + "12.2.0.162" + "\n";
	security_message( data: report );
	exit( 0 );
}

