CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117526" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-01 13:24:22 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 18:38:00 +0000 (Fri, 26 Mar 2021)" );
	script_cve_id( "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS DNSpooq Vulnerabilities (QSA-21-09)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_tag( name: "summary", value: "QNAP QTS is prone to multiple vulnerabilities in dnsmasq." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "DNSpooq vulnerabilities - including DNS cache poisoning and
  buffer overflow vulnerabilities - have been reported to affect certain versions of QTS. If
  exploited, these vulnerabilities allow attackers to perform remote code execution." );
	script_tag( name: "affected", value: "QNAP NAS QTS prior version 4.5.3.1652 build 20210428." );
	script_tag( name: "solution", value: "Update to version 4.5.3.1652 build 20210428 or later." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/QSA-21-09" );
	script_xref( name: "URL", value: "https://www.jsof-tech.com/disclosures/dnspooq/" );
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
if(version_is_less( version: version, test_version: "4.5.3_20210428" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.3_20210428" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

