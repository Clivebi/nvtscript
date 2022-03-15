CPE = "cpe:/a:oracle:jrockit";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813727" );
	script_version( "2021-06-30T02:00:35+0000" );
	script_cve_id( "CVE-2018-2952" );
	script_bugtraq_id( 104765 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-30 02:00:35 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-07-24 17:52:37 +0530 (Tue, 24 Jul 2018)" );
	script_name( "Oracle JRocKit Denial of Service Vulnerability (jul2018-4258247) Windows" );
	script_tag( name: "summary", value: "The host is installed with Oracle JRocKit
  and is prone to a denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  'Concurrency' component of JRockit." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct a denial-of-service condition." );
	script_tag( name: "affected", value: "Oracle JRockit version R28.3.18 and prior." );
	script_tag( name: "solution", value: "Update to Oracle JRockit R28.3.19 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://docs.oracle.com/cd/E15289_01/JRRLN/newchanged.htm#GUID-0DF372A6-33EB-4DD6-AA2D-B4822FF65C03" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixJAVA" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_oracle_jrockit_detect_win.sc" );
	script_mandatory_keys( "JRockit/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("revisions-lib.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
rocVer = infos["version"];
path = infos["location"];
if(( revcomp( a: rocVer, b: "R28.0" ) >= 0 ) && ( revcomp( a: rocVer, b: "R28.3.19" ) < 0 )){
	report = report_fixed_ver( installed_version: rocVer, fixed_version: "R28.3.19", install_path: path );
	security_message( data: report );
	exit( 0 );
}

