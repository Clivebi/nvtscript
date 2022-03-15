CPE = "cpe:/a:clamav:clamav";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813578" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-0360", "CVE-2018-0361" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-26 16:41:00 +0000 (Fri, 26 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-07-17 15:54:58 +0530 (Tue, 17 Jul 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "ClamAV Multiple Vulnerabilities (Jul 2018) - Linux" );
	script_tag( name: "summary", value: "ClamAV is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A lack PDF object length check.

  - HWP integer overflow error in function 'parsehwp3_paragraph' in file
    libclamav/hwp.c." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to cause denial of service and lengthen file parsing time." );
	script_tag( name: "affected", value: "ClamAV version before 0.100.1." );
	script_tag( name: "solution", value: "Update to version 0.100.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://blog.clamav.net/2018/07/clamav-01001-has-been-released.html" );
	script_xref( name: "URL", value: "https://secuniaresearch.flexerasoftware.com/secunia_research/2018-12/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_clamav_remote_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "ClamAV/remote/Ver", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "0.100.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.100.1", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

