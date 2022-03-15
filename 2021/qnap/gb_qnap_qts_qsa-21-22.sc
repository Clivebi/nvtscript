CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146086" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-07 05:02:29 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-09 19:56:00 +0000 (Wed, 09 Jun 2021)" );
	script_cve_id( "CVE-2021-28806" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS XSS Vulnerability (QSA-21-22)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_tag( name: "summary", value: "QNAP QTS is prone to a DOM-based cross-site scripting (XSS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "If exploited, this vulnerability allows attackers to inject
  malicious code." );
	script_tag( name: "affected", value: "QNAP NAS QTS version 4.4.x and 4.5.x prior to
  4.5.3.1652 Build 20210428." );
	script_tag( name: "solution", value: "Update to version 4.5.3.1652 Build 20210428 or later." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/qsa-21-22" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX )){
	exit( 0 );
}
CPE = infos["cpe"];
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.4", test_version2: "4.5.3_20210427" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.3_20210428" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

