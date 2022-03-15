if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105317" );
	script_bugtraq_id( 75525 );
	script_cve_id( "CVE-2015-5352" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_name( "OpenSSH 'x11_open_helper()' Function Security Bypass Vulnerability" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2015-07-09 10:06:32 +0200 (Thu, 09 Jul 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/75525" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to bypass certain security
  restrictions and perform unauthorized actions. This may lead to further attacks" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to 6.9 or newer." );
	script_tag( name: "summary", value: "OpenSSH is prone to a security-bypass vulnerability.

  This NVT has been replaced by OID 1.3.6.1.4.1.25623.1.0.806049." );
	script_tag( name: "affected", value: "OpenSSH < 6.9" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

