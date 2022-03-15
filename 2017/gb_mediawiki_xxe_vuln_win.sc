if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113047" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-09 12:50:51 +0100 (Thu, 09 Nov 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-08 17:09:00 +0000 (Wed, 08 Nov 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-9487" );
	script_name( "MediaWiki XXE Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mediawiki/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "The getid3 library in MediaWiki before 1.24.1, 1.23.8, 1.22.15 and 1.19.23 allows remote attackers to read arbitrary files, cause a denial of service, or possibly have other impact via an XML External Entity (XXE) attack." );
	script_tag( name: "vuldetect", value: "The script checks if the vulnerable version is installed on the host." );
	script_tag( name: "solution", value: "Upgrade MediaWiki to 1.24.1, 1.23.8, 1.22.15 or 1.19.23 respectively." );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1175828" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/01/03/13" );
	script_xref( name: "URL", value: "https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-December/000173.html" );
	exit( 0 );
}
CPE = "cpe:/a:mediawiki:mediawiki";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "1.24.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.24.1" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.23.0", test_version2: "1.23.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.23.8" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.22.0", test_version2: "1.22.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.22.15" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.19.0", test_version2: "1.19.22" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.19.23" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

