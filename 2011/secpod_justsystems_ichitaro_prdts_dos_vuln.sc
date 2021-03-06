if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902396" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)" );
	script_bugtraq_id( 48283 );
	script_cve_id( "CVE-2011-1331" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "JustSystems Ichitaro Products Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_justsystems_ichitaro_prdts_detect.sc" );
	script_mandatory_keys( "Ichitaro/Ichitaro_or_Viewer/Installed" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN87239473/index.html" );
	script_xref( name: "URL", value: "http://www.justsystems.com/jp/info/js11001.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000043.html" );
	script_xref( name: "URL", value: "http://www.symantec.com/connect/blogs/targeted-attacks-2011-using-ichitaro-zero-day-vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code on the
  vulnerable system or cause the application to crash." );
	script_tag( name: "affected", value: "JustSystems Ichitaro version 2005 through 2011

  JustSystems Ichitaro viewer version prior to 20.0.4.0" );
	script_tag( name: "insight", value: "The flaw is due to the error while parsing certain documents." );
	script_tag( name: "summary", value: "This host is installed with JustSystems Ichitaro product(s) and is
  prone to denial of service vulnerability." );
	script_tag( name: "solution", value: "Apply the patch for JustSystems Ichitaro or update to JustSystems Ichitaro viewer version 20.0.4.0 or later." );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:ichitaro:ichitaro",
	 "cpe:/a:justsystem:ichitaro_viewer" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( ContainsString( cpe, "cpe:/a:ichitaro:ichitaro" ) ){
	if(version_in_range( version: vers, test_version: "2005", test_version2: "2011" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(ContainsString( cpe, "cpe:/a:justsystem:ichitaro_viewer" )){
		if(version_is_less( version: vers, test_version: "20.0.4.0" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "20.0.4.0", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

