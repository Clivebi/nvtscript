CPE = "cpe:/a:realnetworks:realplayer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811079" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_cve_id( "CVE-2017-9302" );
	script_bugtraq_id( 98754 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-08 13:48:00 +0000 (Thu, 08 Jun 2017)" );
	script_tag( name: "creation_date", value: "2017-06-05 17:09:15 +0530 (Mon, 05 Jun 2017)" );
	script_name( "RealNetworks RealPlayer 'Divide-By-Zero' Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with RealPlayer
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an improper handling
  of a crafted mp4 file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause divide-by-zero error and crash the application." );
	script_tag( name: "affected", value: "RealNetworks RealPlayer version 16.0.2.32
  on Windows." );
	script_tag( name: "solution", value: "Update to the latest release." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://code610.blogspot.in/2017/05/divided-realplayer-160232.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_realplayer_detect_win.sc" );
	script_mandatory_keys( "RealPlayer/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!realVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(realVer == "16.0.2.32"){
	report = report_fixed_ver( installed_version: realVer, fixed_version: "N/A" );
	security_message( data: report );
	exit( 0 );
}

