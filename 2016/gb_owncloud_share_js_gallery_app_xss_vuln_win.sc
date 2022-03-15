CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809297" );
	script_version( "2019-07-05T10:16:38+0000" );
	script_cve_id( "CVE-2016-7419" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 10:16:38 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-09-26 17:08:33 +0530 (Mon, 26 Sep 2016)" );
	script_name( "ownCloud 'share.js' Gallery Application XSS Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with ownCloud and
  is prone to cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a recent migration
  of the gallery app to the new sharing endpoint and a parameter changed from an
  integer to a string value which is not sanitized properly." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to inject arbitrary web script or HTML." );
	script_tag( name: "affected", value: "ownCloud Server before 9.0.4 on Windows." );
	script_tag( name: "solution", value: "Upgrade to ownCloud Server 9.0.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://owncloud.org/security/advisory/?id=oc-sa-2016-011" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "owncloud/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ownPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ownVer = get_app_version( cpe: CPE, port: ownPort )){
	exit( 0 );
}
if(version_is_less( version: ownVer, test_version: "9.0.4" )){
	report = report_fixed_ver( installed_version: ownVer, fixed_version: "9.0.4" );
	security_message( data: report, port: ownPort );
	exit( 0 );
}
exit( 0 );

