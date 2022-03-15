if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800731" );
	script_version( "2020-06-08T10:12:14+0000" );
	script_tag( name: "last_modification", value: "2020-06-08 10:12:14 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-4655" );
	script_name( "Novell eDirectory 'DHOST' Cookie Hijack Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "novell_edirectory_detect.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "eDirectory/installed" );
	script_xref( name: "URL", value: "http://www.metasploit.com/modules/auxiliary/admin/edirectory/edirectory_dhost_cookie" );
	script_tag( name: "insight", value: "The flaw is due to error in an 'DHOST' module when handling DHOST web
  services. An attacker would wait until the real administrator logs in, then
  specify the predicted cookie value to hijack their session." );
	script_tag( name: "solution", value: "Apply the vendor provided patch." );
	script_tag( name: "summary", value: "This host is running Novell eDirectory is prone to Session Cookie
  hijack vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to hijack arbitrary
  sessions." );
	script_tag( name: "affected", value: "Novell eDirectory version 8.8.5 and prior." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.novell.com/support/kb/doc.php?id=3426981" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
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
edirVer = major + "." + sp;
if(version_in_range( version: edirVer, test_version: "8.8", test_version2: "8.8.5" )){
	report = report_fixed_ver( installed_version: reportver, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

