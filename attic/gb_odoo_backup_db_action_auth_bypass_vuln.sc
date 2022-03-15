if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812757" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-02-08 13:00:22 +0530 (Thu, 08 Feb 2018)" );
	script_name( "Odoo 'Backup Database Action' Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "This VT has been deprecated since CVE-2018-6620 has been rejected.

  The host is running Odoo software and is
  prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request
  and check whether it is able to backup websites databases directly with
  no authorized accounts." );
	script_tag( name: "insight", value: "The flaw exists as Odoo does not require
  authentication to be configured for a 'Backup Database' action." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to backup websites databases directly with no authenticated accounts." );
	script_tag( name: "affected", value: "Odoo Management Software." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://asdedc.bid/odoo.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

