CPE = "cpe:/a:avg:anti-virus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800395" );
	script_version( "2019-11-01T13:58:25+0000" );
	script_tag( name: "last_modification", value: "2019-11-01 13:58:25 +0000 (Fri, 01 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-6662" );
	script_bugtraq_id( 32749 );
	script_name( "Denial of Service vulnerability in AVG Anti-Virus (Linux)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/47254" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2008/3461" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_avg_av_detect_lin.sc" );
	script_mandatory_keys( "avg/antivirus/detected" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code in the
  context of the affected application or even can cause denial of service." );
	script_tag( name: "affected", value: "AVG Anti-Virus version 7.5.51 and prior on Linux." );
	script_tag( name: "insight", value: "The flaw is caused by a memory corruption error when the scan engine processes
  malformed UPX files." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with AVG Anti-Virus and is prone to Denial
  of Service Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "7.5.51" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

