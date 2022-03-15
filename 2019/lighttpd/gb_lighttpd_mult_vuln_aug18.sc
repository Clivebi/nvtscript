CPE = "cpe:/a:lighttpd:lighttpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108549" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_cve_id( "CVE-2018-19052" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-21 00:15:00 +0000 (Mon, 21 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-02-19 10:42:10 +0100 (Tue, 19 Feb 2019)" );
	script_name( "Lighttpd < 1.4.50 Multiple Vulnerabilities" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_dependencies( "sw_lighttpd_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lighttpd/installed" );
	script_xref( name: "URL", value: "https://www.lighttpd.net/2018/8/13/1.4.50/" );
	script_xref( name: "URL", value: "https://redmine.lighttpd.net/issues/2898" );
	script_xref( name: "URL", value: "https://github.com/lighttpd/lighttpd1.4/commit/2105dae0f9d7a964375ce681e53cb165375f84c1" );
	script_tag( name: "summary", value: "This host is running Lighttpd which is prone to
  multiple path traversal and use-after-free vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation might allow a remote
  attacker to execute arbitrary code on affected system or conduct path traversal
  attacks to get unauthorized access to files on the hosts filesystem." );
	script_tag( name: "affected", value: "Lighttpd versions before 1.4.50." );
	script_tag( name: "solution", value: "Upgrade to version 1.4.50 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.4.50" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.50" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

