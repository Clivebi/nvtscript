CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805972" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_cve_id( "CVE-2015-1042" );
	script_bugtraq_id( 71988 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-09-07 12:56:25 +0530 (Mon, 07 Sep 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "MantisBT Open Redirect Vulnerability September15 (Windows)" );
	script_tag( name: "summary", value: "This host is running MantisBT and is prone
  to open redirect vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to use of an incorrect regular
  expression within string_sanitize_url function in core/string_api.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing." );
	script_tag( name: "affected", value: "MantisBT versions 1.2.0a3 through 1.2.18
  on Windows" );
	script_tag( name: "solution", value: "Upgrade to version 1.2.19 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/130142" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jan/110" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/01/10/5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!mantisPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!mantisVer = get_app_version( cpe: CPE, port: mantisPort )){
	exit( 0 );
}
if(version_in_range( version: mantisVer, test_version: "1.2.0", test_version2: "1.2.18" )){
	report = report_fixed_ver( installed_version: mantisVer, fixed_version: "1.2.19" );
	security_message( data: report, port: mantisPort );
	exit( 0 );
}
exit( 99 );

