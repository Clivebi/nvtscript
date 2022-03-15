CPE = "cpe:/a:spip:spip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809766" );
	script_version( "2019-04-17T12:01:26+0000" );
	script_cve_id( "CVE-2016-9998", "CVE-2016-9997" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-04-17 12:01:26 +0000 (Wed, 17 Apr 2019)" );
	script_tag( name: "creation_date", value: "2016-12-19 14:42:01 +0530 (Mon, 19 Dec 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "SPIP 'plugin' and 'id' Parameters Multiple Cross-Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with SPIP
  and is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an insufficient
  validation of input passed via the 'id' parameter to the '/ecrire/exec/puce_statut.php'
  script and the 'plugin' parameter to the '/ecrire/exec/info_plugin.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "SPIP version 3.1.x through 3.1.3." );
	script_tag( name: "solution", value: "Update to 3.1.4." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://core.spip.net/projects/spip/repository/revisions/23288" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_spip_detect.sc" );
	script_mandatory_keys( "spip/detected" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!sp_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: sp_port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_in_range( version: version, test_version: "3.1.0", test_version2: "3.1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.4", install_path: path );
	security_message( port: sp_port, data: report );
	exit( 0 );
}
exit( 99 );

