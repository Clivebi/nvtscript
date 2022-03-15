if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100343" );
	script_version( "2020-06-08T10:12:14+0000" );
	script_tag( name: "last_modification", value: "2020-06-08 10:12:14 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2009-11-13 12:21:24 +0100 (Fri, 13 Nov 2009)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4653" );
	script_bugtraq_id( 37009 );
	script_name( "Novell eDirectory '/dhost/modules?I:' Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "novell_edirectory_detect.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "eDirectory/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37009" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/507812" );
	script_tag( name: "summary", value: "Novell eDirectory is prone to a buffer-overflow vulnerability
  because it fails to perform adequate boundary checks on user-supplied data." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will likely cause denial-of-service conditions." );
	script_tag( name: "affected", value: "Novell eDirectory 8.8 SP5 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
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
revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );
instver = major;
if(sp > 0){
	instver += " SP" + sp;
}
if( major == "8.8" ){
	if( sp && sp > 0 ){
		if(sp == 5){
			if(!revision){
				VULN = TRUE;
			}
		}
		if(sp < 5){
			VULN = TRUE;
		}
	}
	else {
		VULN = TRUE;
	}
}
else {
	if( major == "8.8.1" ){
		VULN = TRUE;
	}
	else {
		if(major == "8.8.2"){
			if(!revision && !sp){
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: instver, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

