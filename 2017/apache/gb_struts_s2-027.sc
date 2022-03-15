CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812064" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2016-3090" );
	script_bugtraq_id( 85131 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-01 01:29:00 +0000 (Sun, 01 Jul 2018)" );
	script_tag( name: "creation_date", value: "2017-11-02 15:00:36 +0530 (Thu, 02 Nov 2017)" );
	script_name( "Apache Struts Security Update (S2-027)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-027" );
	script_xref( name: "Advisory-ID", value: "S2-027" );
	script_tag( name: "summary", value: "Apache Struts is prone to a remote code execution
  (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  'TextParseUtil.translateVariables' method which does not filter malicious OGNL
  expressions." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to
  execute arbitrary code in the context of the affected application. Failed exploit
  attempts may cause a denial of service (DoS) condition." );
	script_tag( name: "affected", value: "Apache Struts 2.0.0 through 2.3.16.3." );
	script_tag( name: "solution", value: "Update to version 2.3.24.1 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(version_in_range( version: vers, test_version: "2.0.0", test_version2: "2.3.16.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.24.1", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

