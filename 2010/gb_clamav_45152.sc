if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100932" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-12-02 19:42:22 +0100 (Thu, 02 Dec 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-4260" );
	script_bugtraq_id( 45152 );
	script_name( "ClamAV Prior to 0.96.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_clamav_detect_lin.sc", "gb_clamav_detect_win.sc", "gb_clamav_remote_detect.sc" );
	script_mandatory_keys( "ClamAV/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45152" );
	script_xref( name: "URL", value: "http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=1f3db7f074995bd4e1d0183b2db8b1c472d2f41b" );
	script_xref( name: "URL", value: "http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=019f1955194360600ecf0644959ceca6734c2d7b" );
	script_xref( name: "URL", value: "http://freshmeat.net/projects/clamav/releases/325193" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "ClamAV is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "Versions prior to ClamAV 0.96.5 are vulnerable." );
	script_tag( name: "impact", value: "Attackers may exploit these issues to cause denial-of-service
  conditions or potentially execute arbitrary code in the context of the application." );
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
if(version_is_less( version: ver, test_version: "0.96.5" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "0.96.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

