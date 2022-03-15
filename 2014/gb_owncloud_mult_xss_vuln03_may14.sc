CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804284" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2013-2150" );
	script_bugtraq_id( 60416 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-05-06 16:30:55 +0530 (Tue, 06 May 2014)" );
	script_name( "ownCloud Multiple Cross Site Scripting Vulnerabilities -03 May14" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to multiple cross-site
scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to insufficient validation of user-supplied input
passed via the unspecified vectors to js/viewer.js script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
script code in a user's browser within the trust relationship between their
browser and the server." );
	script_tag( name: "affected", value: "ownCloud Server before version 4.5.12 and 5.0.x before version 5.0.7" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 4.5.12 or 5.0.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q2/514" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/oc-sa-2013-028" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
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
if(version_is_less( version: ownVer, test_version: "4.5.12" ) || version_in_range( version: ownVer, test_version: "5.0.0", test_version2: "5.0.6" )){
	security_message( port: ownPort );
	exit( 0 );
}

