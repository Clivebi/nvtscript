if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103083" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-02-22 13:26:53 +0100 (Tue, 22 Feb 2011)" );
	script_bugtraq_id( 46470 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-1003" );
	script_name( "ClamAV 'vba_read_project_strings()' Double Free Memory Corruption Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_clamav_detect_lin.sc", "gb_clamav_detect_win.sc", "gb_clamav_remote_detect.sc" );
	script_mandatory_keys( "ClamAV/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46470" );
	script_xref( name: "URL", value: "https://wwws.clamav.net/bugzilla/show_bug.cgi?id=2486" );
	script_xref( name: "URL", value: "http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=d21fb8d975f8c9688894a8cef4d50d977022e09f" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "ClamAV is prone to a double-free memory-corruption
  vulnerability." );
	script_tag( name: "affected", value: "Versions prior to ClamAV 0.97 are vulnerable." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause denial-of-service
  conditions. Due to the nature of this issue, arbitrary code execution
  may be possible. This has not been confirmed." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
ver = get_kb_item( "ClamAV/remote/Ver" );
if(!ver){
	ver = get_kb_item( "ClamAV/Lin/Ver" );
	if(!ver){
		ver = get_kb_item( "ClamAV/Win/Ver" );
	}
}
if(!ver){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "0.97" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "0.97" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

