if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801642" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)" );
	script_cve_id( "CVE-2010-3915", "CVE-2010-3916" );
	script_bugtraq_id( 44637 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "JustSystems Ichitaro Multiple Remote Code Execution Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_justsystems_ichitaro_prdts_detect.sc" );
	script_mandatory_keys( "Ichitaro/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code
  within the context of the vulnerable application." );
	script_tag( name: "affected", value: "JustSystems Ichitaro 2004 through 2010." );
	script_tag( name: "insight", value: "The flaws are caused by an unspecified error when processing a malformed
  document, which could be exploited to execute arbitrary code." );
	script_tag( name: "summary", value: "This host is installed JustSystems Ichitaro and is prone to
  multiple code execution vulnerabilities." );
	script_tag( name: "solution", value: "Apply the referenced patch." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/62997" );
	script_xref( name: "URL", value: "http://www.justsystems.com/jp/info/js10003.html" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2885" );
	script_xref( name: "URL", value: "http://www.justsystems.com/jp/info/js10003.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
CPE = "cpe:/a:ichitaro:ichitaro";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2004", test_version2: "2010" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "2004 - 2010", fixed_version: "Apply the referenced patch" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

