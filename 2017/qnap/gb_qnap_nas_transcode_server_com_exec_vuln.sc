CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811727" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2017-13067" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-09-01 10:43:16 +0530 (Fri, 01 Sep 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "QNAP NAS 'Transcode Server' Command Execution Vulnerability" );
	script_tag( name: "summary", value: "This host is running QNAP NAS device and
  is prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to error in 'rmfile' command
  in Transcode Server which does not filter certain special characters and allow
  them to pass in the command." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary commands on the remote affected device." );
	script_tag( name: "affected", value: "QNAP TS-431 with firmware version 4.3.3.0262
  (20170727) and QNAP_TS-131. Many other QNAP models may also be affected." );
	script_tag( name: "solution", value: "Upgrade to the latest version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.exploitee.rs/index.php/QNAP_TS-131" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/42587" );
	script_xref( name: "URL", value: "https://www.cvedetails.com/cve/cve-2017-13067" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_require_ports( "Services/www", 80, 8080 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!model = get_kb_item( "qnap/dismodel" )){
	exit( 0 );
}
if(!IsMatchRegexp( model, "(TS-131|TS-431)" )){
	exit( 0 );
}
if(!version = get_kb_item( "qnap/version" )){
	exit( 0 );
}
if(!build = get_kb_item( "qnap/build" )){
	exit( 0 );
}
checkvers = version + "." + build;
if(( model == "TS-431" && checkvers == "4.3.3.0262.20170727" ) || ( model == "TS-131" )){
	report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3.0299.20170901" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

