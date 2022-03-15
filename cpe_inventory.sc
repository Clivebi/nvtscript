if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810002" );
	script_version( "2021-04-16T10:39:13+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 10:39:13 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-11-18 11:43:05 +0100 (Wed, 18 Nov 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "CPE Inventory" );
	script_category( ACT_END );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_xref( name: "URL", value: "https://nvd.nist.gov/products/cpe" );
	script_tag( name: "summary", value: "This routine uses information collected by other routines about
  CPE identities of operating systems, services and applications detected during the scan.

  Note: Some CPEs for specific products might show up twice or more in the output. Background:

  After a product got renamed or a specific vendor was acquired by another one it might happen that a
  product gets a new CPE within the NVD CPE Dictionary but older entries are kept with the older CPE." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
ip = get_host_ip();
report = "";
cpes = host_details_cpes();
cpes = sort( cpes );
for cpe in cpes {
	if(!ContainsString( report, cpe )){
		report += ip + "|" + cpe + "\n";
	}
}
if(report != ""){
	set_kb_item( name: "cpe_inventory/available", value: TRUE );
	log_message( proto: "CPE-T", data: report );
}
exit( 0 );

