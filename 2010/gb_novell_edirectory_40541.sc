if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100667" );
	script_version( "2020-06-08T10:12:14+0000" );
	script_tag( name: "last_modification", value: "2020-06-08 10:12:14 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-06-04 13:05:19 +0200 (Fri, 04 Jun 2010)" );
	script_bugtraq_id( 40541 );
	script_cve_id( "CVE-2009-4653" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_name( "Novell eDirectory Multiple Remote Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "novell_edirectory_detect.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "eDirectory/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40541" );
	script_xref( name: "URL", value: "http://www.novell.com/support/viewContent.do?externalId=3426981" );
	script_xref( name: "URL", value: "http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5076150.html" );
	script_xref( name: "URL", value: "http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5076151.html" );
	script_tag( name: "solution", value: "The vendor has released fixes. Please see the references for details." );
	script_tag( name: "summary", value: "Novell eDirectory is prone to multiple remote vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploits may allow attackers to execute arbitrary code
  within the context of the affected application or cause denial-of-service conditions." );
	script_tag( name: "affected", value: "These issues affect eDirectory versions prior to 8.8 SP5 Patch 4." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:novell:edirectory",
	 "cpe:/a:netiq:edirectory" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!major = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(!sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" )){
	sp = "0";
}
reportver = major;
if(sp > 0){
	reportver += " SP" + sp;
}
revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );
revision = str_replace( string: revision, find: ".", replace: "" );
if(major == "8.8"){
	if( sp && sp > 0 ){
		if( sp == 5 ){
			if(revision && int( revision ) < 2050413){
				vuln = TRUE;
			}
		}
		else {
			if(sp < 5){
				vuln = TRUE;
			}
		}
	}
	else {
		vuln = TRUE;
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: reportver, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

