CPE = "cpe:/a:wibu:codemeter_webadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802382" );
	script_version( "2020-03-04T06:31:22+0000" );
	script_cve_id( "CVE-2011-4057" );
	script_bugtraq_id( 51382 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 06:31:22 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2012-01-19 15:06:52 +0530 (Thu, 19 Jan 2012)" );
	script_name( "Wibu-Systems CodeMeter Runtime TCP Packets Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_codemeter_webadmin_detect.sc" );
	script_mandatory_keys( "wibu/codemeter_webadmin/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47497" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/659515" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN78901873/index.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000003.html" );
	script_tag( name: "impact", value: "Successful exploitation will enable attackers to cause a denial of service condition." );
	script_tag( name: "affected", value: "Wibu-Systems CodeMeter version before 4.40." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error which fails to handle
  crafted packets to TCP port 22350." );
	script_tag( name: "solution", value: "Upgrade to Wibu-Systems CodeMeter version 4.40 or later." );
	script_tag( name: "summary", value: "The host is running Wibu-Systems CodeMeter Runtime and is prone to denial of service
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "4.40" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.40", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

