if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808247" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2015-5664" );
	script_bugtraq_id( 91474 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-07-05 16:44:34 +0530 (Tue, 05 Jul 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "QNAP QTS File Station Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is running QNAP QTS File Station
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient validation
  of user supplied input via unspecified vectors in File Station." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via unspecified vectors." );
	script_tag( name: "affected", value: "QNAP QTS versions prior to 4.2.0" );
	script_tag( name: "solution", value: "Upgrade to QNAP QTS version
  4.2.1 Build 20160601 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN42930233/index.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000119.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_require_ports( "Services/www", 80, 8080 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!qtsPort = get_kb_item( "qnap/port" )){
	exit( 0 );
}
if(!version = get_kb_item( "qnap/version" )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.1 Build 20160601" );
	security_message( port: qtsPort, data: report );
	exit( 0 );
}
exit( 0 );

