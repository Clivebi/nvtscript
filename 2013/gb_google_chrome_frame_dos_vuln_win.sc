if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803461" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-2493" );
	script_bugtraq_id( 58562 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-04-02 12:21:11 +0530 (Tue, 02 Apr 2013)" );
	script_name( "Google Chrome Frame Plugin For Microsoft IE Denial Of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "https://chromiumcodereview.appspot.com/12395021" );
	script_xref( name: "URL", value: "https://code.google.com/p/chromium/issues/detail?id=178415" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2013/03/beta-channel-update.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to crash the
  program via a specially crafted _blank value for the target
  attribute of an A element." );
	script_tag( name: "affected", value: "Google Chrome Frame plugin version before 26.0.1410.28" );
	script_tag( name: "insight", value: "Flaw due to an improper handling of an attach tab request in the
  Hook_Terminate function in chrome_frame/protocol_sink_wrap.cc." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome Frame plugin 26.0.1410.28 or later." );
	script_tag( name: "summary", value: "This host is installed with google chrome frame plugin for
  microsoft ie and is prone to denial of service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.google.com/chromeframe" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome Frame";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
name = registry_get_sz( item: "DisplayName", key: key );
if(ContainsString( name, "Google Chrome Frame" )){
	ver = registry_get_sz( item: "Version", key: key );
	if(ver){
		if(version_is_less( version: ver, test_version: "26.0.1410.28" )){
			report = report_fixed_ver( installed_version: ver, fixed_version: "26.0.1410.28" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}

