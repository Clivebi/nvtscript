CPE = "cpe:/a:ntop:ntopng";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112105" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-06 15:50:16 +0200 (Mon, 06 Nov 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-29 15:31:00 +0000 (Thu, 29 Jun 2017)" );
	script_cve_id( "CVE-2017-7458", "CVE-2017-7459", "CVE-2017-7416" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ntopng < 3.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ntopng_detect.sc" );
	script_mandatory_keys( "ntopng/detected" );
	script_tag( name: "summary", value: "ntopng is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2017-7458: The NetworkInterface::getHost function in NetworkInterface.cpp allows remote
    attackers to cause a denial of service (NULL pointer dereference and application crash) via
    an empty field that should have contained a hostname or IP address.

  - CVE-2017-7459: HTTP Response Splitting

  - CVE-2017-7416: Cross-site scripting (XSS) because GET and POST parameters are improperly
    validated" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to cause a
  denial of service and/or inject arbitrary script code." );
	script_tag( name: "affected", value: "ntopng prior to version 3.0" );
	script_tag( name: "solution", value: "Upgrade to ntopng 3.0 or later." );
	script_xref( name: "URL", value: "https://github.com/ntop/ntopng/blob/3.0/CHANGELOG.md" );
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
if(version_is_less( version: version, test_version: "3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

