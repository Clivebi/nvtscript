if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113004" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-27 14:27:13 +0200 (Wed, 27 Sep 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-28 18:33:00 +0000 (Thu, 28 Sep 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-3431", "CVE-2015-3432" );
	script_bugtraq_id( 74596 );
	script_name( "Pydio < 6.0.7 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pydio_detect.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_mandatory_keys( "pydio/installed" );
	script_tag( name: "summary", value: "The host is running and older version of Pydio which is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Pydio version <6.0.7 is prone to XSS and command injection vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation allows the attacker change the contents of the Webpage and send a link
  to victims. Furthermore, an attacker could run arbitrary commands on the host." );
	script_tag( name: "affected", value: "Pydio version before 6.0.7." );
	script_tag( name: "solution", value: "Update to Pydio version 6.0.7." );
	script_xref( name: "URL", value: "https://pydio.com/en/community/releases/pydio-core/pydio-607-security-release" );
	exit( 0 );
}
CPE = "cpe:/a:pydio:pydio";
require("misc_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.0.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

