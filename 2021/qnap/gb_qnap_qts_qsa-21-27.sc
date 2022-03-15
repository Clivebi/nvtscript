CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146152" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-18 08:07:52 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-24 18:30:00 +0000 (Thu, 24 Jun 2021)" );
	script_cve_id( "CVE-2021-20254" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS SMB Vulnerability (QSA-21-27)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_tag( name: "summary", value: "QNAP QTS is prone to an SMB out-of-bounds read vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An SMB out-of-bounds read vulnerability has been reported to
  affect QNAP NAS running QTS. If exploited, this vulnerability allows attackers to obtain
  sensitive information on the system." );
	script_tag( name: "affected", value: "QNAP NAS QTS prior version 4.5.3.1670 Build 20210515." );
	script_tag( name: "solution", value: "Update to version 4.5.3.1670 Build 20210515 or later." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/QSA-21-27" );
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
if(version_is_less( version: version, test_version: "4.5.3_20210515" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.3_20210515" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

