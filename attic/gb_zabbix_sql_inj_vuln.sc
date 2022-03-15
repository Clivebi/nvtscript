if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106613" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-20 16:42:02 +0700 (Mon, 20 Feb 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_cve_id( "CVE-2016-10134" );
	script_bugtraq_id( 95423 );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Zabbix SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "summary", value: "Zabbix is prone to a SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "SQL injection vulnerability in Zabbix allows remote attackers to execute
  arbitrary SQL commands via the toggle_ids array parameter in latest.php." );
	script_tag( name: "affected", value: "Zabbix version 2.2.x and 3.0.x" );
	script_tag( name: "solution", value: "Update to 2.2.14, 3.0.4 or newer versions." );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-11023" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

