CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141566" );
	script_version( "2021-05-26T08:25:33+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 08:25:33 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-10-05 10:33:07 +0700 (Fri, 05 Oct 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-23 18:24:00 +0000 (Fri, 23 Nov 2018)" );
	script_cve_id( "CVE-2018-13258" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MediaWiki 1.31.0 .htaccess Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mediawiki/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Mediawiki misses .htaccess files in the provided tarball used to protect some
directories that shouldn't be web accessible." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "MediaWiki version 1.30.x." );
	script_tag( name: "solution", value: "Update to version 1.30.1 or later." );
	script_xref( name: "URL", value: "https://lists.wikimedia.org/pipermail/wikitech-l/2018-September/090849.html" );
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
if(IsMatchRegexp( version, "^1\\.30\\.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.30.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

