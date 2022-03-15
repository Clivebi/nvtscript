CPE = "cpe:/a:cybozu:office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807279" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-8483" );
	script_bugtraq_id( 83290 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-03 18:23:59 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cybozuo Office Open Redirect Vulnerability Feb16" );
	script_tag( name: "summary", value: "The host is installed with Cybozu Office
  and is prone to Open Redirect Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  network functions." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to redirect users to arbitrary web sites and conduct phishing
  attacks via a crafted URL." );
	script_tag( name: "affected", value: "Cybozu Office version 10.2.0 to 10.3.0" );
	script_tag( name: "solution", value: "Upgrade to Cybozu Office version 10.4.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN71428831/index.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_mandatory_keys( "CybozuOffice/Installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!cybPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!cybVer = get_app_version( port: cybPort, cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: cybVer, test_version: "10.2.0", test_version2: "10.3.0" )){
	report = report_fixed_ver( installed_version: cybVer, fixed_version: "10.4.0" );
	security_message( port: cybPort, data: report );
	exit( 0 );
}
exit( 99 );

