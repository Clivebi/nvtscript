if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800998" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-0937" );
	script_bugtraq_id( 37644 );
	script_name( "Visualization Library Multiple Unspecified Vulnerabilities (Linux)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55478" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0050" );
	script_xref( name: "URL", value: "http://visualizationlibrary.com/documentation/pagchangelog.html" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_visualization_library_detect_lin.sc" );
	script_mandatory_keys( "VisualizationLibrary/Linux/Ver" );
	script_tag( name: "impact", value: "Unknown impacts and unknown attack vectors." );
	script_tag( name: "affected", value: "Visualization Library versions prior to 2009.08.812 on Linux" );
	script_tag( name: "insight", value: "The flaws are caused by multiple unspecified errors with unknown impact and
  unknown attack vectors." );
	script_tag( name: "solution", value: "Update to version 2009.08.812 or above." );
	script_tag( name: "summary", value: "The host is running Visualization Library and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.visualizationlibrary.com/downloads.php" );
	exit( 0 );
}
require("version_func.inc.sc");
vslVer = get_kb_item( "VisualizationLibrary/Linux/Ver" );
if(isnull( vslVer )){
	exit( 0 );
}
if(version_is_less( version: vslVer, test_version: "2009.08.812" )){
	report = report_fixed_ver( installed_version: vslVer, fixed_version: "2009.08.812" );
	security_message( port: 0, data: report );
}

