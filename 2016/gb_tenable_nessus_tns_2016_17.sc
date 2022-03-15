CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108019" );
	script_version( "2019-12-18T08:41:29+0000" );
	script_cve_id( "CVE-2016-9259" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-12-18 08:41:29 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-11-11 13:00:00 +0100 (Fri, 11 Nov 2016)" );
	script_name( "Tenable Nessus < 6.9.1 Stored Cross-Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nessus_web_server_detect.sc" );
	script_mandatory_keys( "nessus/installed" );
	script_tag( name: "summary", value: "This host is installed with Nessus and is prone to
  a stored Cross-Site Scripting vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML." );
	script_tag( name: "affected", value: "Tenable Nessus versions 6.8.0, 6.8.1, 6.8.2 and 6.9.0" );
	script_tag( name: "solution", value: "Upgrade Tenable Nessus to 6.9.1." );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2016-17" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "6.8.0", test_version2: "6.9.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.9.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

