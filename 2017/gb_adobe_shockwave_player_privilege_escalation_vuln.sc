CPE = "cpe:/a:adobe:shockwave_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810816" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2017-2983" );
	script_bugtraq_id( 96863 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-17 13:18:00 +0000 (Mon, 17 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-17 11:52:16 +0530 (Fri, 17 Mar 2017)" );
	script_name( "Adobe Shockwave Player Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave
  Player and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insecure library
  loading (DLL hijacking) vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to elevate privileges." );
	script_tag( name: "affected", value: "Adobe Shockwave Player version before
  12.2.8.198 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Shockwave Player version
  12.2.8.198 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/shockwave/apsb17-08.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "12.2.8.198" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.2.8.198" );
	security_message( data: report );
	exit( 0 );
}

