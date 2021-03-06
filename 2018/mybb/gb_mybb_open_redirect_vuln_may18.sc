CPE = "cpe:/a:mybb:mybb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813403" );
	script_version( "2021-08-13T07:21:38+0000" );
	script_cve_id( "CVE-2018-10678" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 07:21:38 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-05 13:03:00 +0000 (Tue, 05 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-05-22 15:25:41 +0530 (Tue, 22 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "MyBB Open Redirection Vulnerability-May18" );
	script_tag( name: "summary", value: "The host is installed with MyBB and is
  prone to open redirection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as application fails to
  properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct phishing attacks. Other attacks are also possible." );
	script_tag( name: "affected", value: "MyBB version 1.8.15" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://gist.github.com/MayurUdiniya/7aaa50b878d82b6aab6ed0b3e2b080bc" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_mybb_detect.sc" );
	script_mandatory_keys( "MyBB/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version == "1.8.15"){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

