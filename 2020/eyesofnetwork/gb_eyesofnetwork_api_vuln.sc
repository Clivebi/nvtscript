CPE = "cpe:/a:eyes_of_network:eyes_of_network";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143504" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-02-11 07:27:24 +0000 (Tue, 11 Feb 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-23 15:07:00 +0000 (Tue, 23 Feb 2021)" );
	script_cve_id( "CVE-2020-8656", "CVE-2020-8657" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Eyes Of Network (EON) Multiple API Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_eyesofnetwork_detect.sc" );
	script_mandatory_keys( "eyesofnetwork/api/version" );
	script_require_ports( "Services/www", 80, 443 );
	script_tag( name: "summary", value: "Eyes Of Network (EON) is prone to multiple vulnerabilities over the API." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Eyes Of Network (EON) is prone to multiple vulnerabilities:

  - SQL injection vulnerability allowing an unauthenticated attacker to perform various tasks such as
    authentication bypass (CVE-2020-8656)

  - Hardcoded EONAPI_KEY allowing an attacker to calculate/guess the admin access token (CVE-2020-8657)" );
	script_tag( name: "affected", value: "Eyes Of Network API version 2.4.2 and probably prior." );
	script_tag( name: "solution", value: "See the referenced vendor advisories for a solution." );
	script_xref( name: "URL", value: "https://github.com/EyesOfNetworkCommunity/eonapi/issues/16" );
	script_xref( name: "URL", value: "https://github.com/EyesOfNetworkCommunity/eonapi/issues/17" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/156266/EyesOfNetwork-5.3-Remote-Code-Execution.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
if(!version = get_kb_item( "eyesofnetwork/api/version" )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.4.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisories." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

