CPE = "cpe:/a:phpipam:phpipam";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106700" );
	script_version( "$Revision: 12338 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2017-03-28 11:42:33 +0700 (Tue, 28 Mar 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2017-6481" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "phpIPAM <= 1.2.1 Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ipam_detect.sc" );
	script_mandatory_keys( "phpipam/installed" );
	script_tag( name: "summary", value: "phpIPAM is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerabilities exist due to insufficient filtration of user-supplied
  data passed to several pages (instructions in app/admin/instructions/preview.php subnetId in
  app/admin/powerDNS/refresh-ptr-records.php)." );
	script_tag( name: "impact", value: "An attacker could execute arbitrary HTML and script code in a browser in the
  context of the vulnerable website." );
	script_tag( name: "affected", value: "phpIPAM 1.2.1 and prior." );
	script_tag( name: "solution", value: "Update to phpIPAM 1.3 or later." );
	script_xref( name: "URL", value: "https://phpipam.net/documents/changelog/" );
	script_xref( name: "URL", value: "https://github.com/phpipam/phpipam/issues/992" );
	script_xref( name: "URL", value: "http://phpipam.net" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "1.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3 or later." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

