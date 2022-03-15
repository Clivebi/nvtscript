if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112357" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-1000218", "CVE-2018-1000219" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 19:14:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2018-08-21 09:48:12 +0200 (Tue, 21 Aug 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "OpenEMR <= 5.0.1.4 XSS Vulnerabilities" );
	script_tag( name: "summary", value: "OpenEMR is prone to multiple cross-site scripting (XSS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws consist of multiple XSS vulnerabilities in the 'scan' and 'file' parameter of 'interface/fax/fax_view.php'." );
	script_tag( name: "affected", value: "OpenEMR versions up to and including 5.0.1.4." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://github.com/openemr/openemr/pull/1783" );
	script_xref( name: "URL", value: "https://github.com/openemr/openemr/issues/1781" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openemr_detect.sc" );
	script_mandatory_keys( "openemr/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:open-emr:openemr";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "5.0.1-4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See references", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

