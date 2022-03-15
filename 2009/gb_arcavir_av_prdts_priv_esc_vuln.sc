if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800720" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 35100 );
	script_cve_id( "CVE-2009-1824" );
	script_name( "ArcaVir AntiVirus Products Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35260" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8782" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1428" );
	script_xref( name: "URL", value: "http://ntinternals.org/ntiadv0814/ntiadv0814.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_arcavir_av_prdts_detect.sc" );
	script_mandatory_keys( "ArcaVir/AntiVirus/Ver" );
	script_tag( name: "affected", value: "ArcaBit 2009 Home Protection prior to 9.4.3204.9

  ArcaVir 2009 System Protection prior to 9.4.3203.9

  ArcaVir 2009 Internet Security prior to 9.4.3202.9

  ArcaBit ArcaVir 2009 Antivirus Protection prior to 9.4.3201.9" );
	script_tag( name: "insight", value: "This flaw is due to vulnerability in ps_drv.sys driver, which allows any users
  to open the device '\\\\Device\\\\ps_drv' and issue IOCTLs with a buffering mode of
  METHOD_NEITHER." );
	script_tag( name: "solution", value: "Apply the security updates accordingly." );
	script_tag( name: "summary", value: "This host is running ArcaVir AntiVirus Products and is prone to Privilege
  Escalation Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker pass kernel addresses as the
  arguments to the driver and overwrite an arbitrary address in the kernel space
  through a specially crafted IOCTL." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
arvaavVer = get_kb_item( "ArcaVir/AntiVirus/Ver" );
if(!arvaavVer){
	exit( 0 );
}
if(version_is_less( version: arvaavVer, test_version: "9.4.3201.9" )){
	report = report_fixed_ver( installed_version: arvaavVer, fixed_version: "9.4.3201.9" );
	security_message( port: 0, data: report );
}

