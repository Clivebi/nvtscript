CPE = "cpe:/a:proftpd:proftpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143205" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-11-29 03:21:30 +0000 (Fri, 29 Nov 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-11 18:10:00 +0000 (Wed, 11 Dec 2019)" );
	script_cve_id( "CVE-2019-19271", "CVE-2019-19272" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ProFTPD < 1.3.6 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "secpod_proftpd_server_detect.sc" );
	script_mandatory_keys( "ProFTPD/Installed" );
	script_tag( name: "summary", value: "ProFTPD is prone to multiple vulnerabilities in the handling of CRLs in mod_tls." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "ProFTPD versions prior to 1.3.6." );
	script_tag( name: "solution", value: "Update to version 1.3.6 or later." );
	script_xref( name: "URL", value: "https://github.com/proftpd/proftpd/issues/860" );
	script_xref( name: "URL", value: "https://github.com/proftpd/proftpd/issues/858" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.3.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

