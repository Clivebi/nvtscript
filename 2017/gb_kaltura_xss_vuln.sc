CPE = "cpe:/a:kaltura:kaltura";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106629" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-03 13:38:08 +0700 (Fri, 03 Mar 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-07 02:59:00 +0000 (Tue, 07 Mar 2017)" );
	script_cve_id( "CVE-2017-6391", "CVE-2017-6392" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Kaltura Server Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_kaltura_community_edition_detect.sc" );
	script_mandatory_keys( "kaltura/installed" );
	script_tag( name: "summary", value: "Kaltura Server is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Kaltura Server is prone to multiple XSS vulnerabilities:

  - XSS vulnerability in SimpleJWPlayer.php, AkamaiBroadcaster.php, bigRedButton.php and bigRedButtonPtsPoc.php
(CVE-2017-6391)

  - XSS vulnerability in XmlJWPlayer.php (CVE-2017-6392)" );
	script_tag( name: "affected", value: "Kaltura Server 12.11.0 and prior." );
	script_tag( name: "solution", value: "Apply the provided patch." );
	script_xref( name: "URL", value: "https://github.com/kaltura/server/issues/5300" );
	script_xref( name: "URL", value: "https://github.com/kaltura/server/issues/5303" );
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
if(version_is_less_equal( version: version, test_version: "12.11.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

