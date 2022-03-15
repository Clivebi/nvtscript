CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811314" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2014-9469" );
	script_bugtraq_id( 72592 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 14:52:00 +0000 (Fri, 01 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-08-31 12:28:37 +0530 (Thu, 31 Aug 2017)" );
	script_name( "vBulletin Forum 'forum/help' Page Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with vBulletin and is prone
  to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the programming code
  flaw occurs at 'forum/help' page. Add 'hash symbol' first. Then add script at
  the end of it." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to execute arbitrary script code in the browser of an
  unsuspecting user in the context of the affected site. This may allow the
  attacker to steal cookie-based authentication credentials and launch other
  attacks." );
	script_tag( name: "affected", value: "vBulletin versions 5.1.3, 5.0.5, 4.2.2, 3.8.7,
  3.6.7, 3.6.0 and 3.5.4." );
	script_tag( name: "solution", value: "Update to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://vuldb.com/?id.69174" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Feb/49" );
	script_xref( name: "URL", value: "http://www.tetraph.com/blog/xss-vulnerability/cve-2014-9469-vbulletin-xss" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "vbulletin_detect.sc" );
	script_mandatory_keys( "vbulletin/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
for affected_version in make_list( "5.1.3",
	 "5.0.5",
	 "4.2.2",
	 "3.8.7",
	 "3.6.7",
	 "3.6.0",
	 "3.5.4" ) {
	if(affected_version == vers){
		report = report_fixed_ver( installed_version: vers, fixed_version: "Ask vendor", install_path: path );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

