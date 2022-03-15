if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143039" );
	script_version( "2021-09-20T15:26:26+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 15:26:26 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-10-23 06:34:37 +0000 (Wed, 23 Oct 2019)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 20:29:00 +0000 (Mon, 03 Jun 2019)" );
	script_cve_id( "CVE-2019-1543", "CVE-2019-2920" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server 5.3 <= 5.3.13 / 8.0 <= 8.0.17 Security Update (cpuoct2019) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to a vulnerability.

  This VT has been deprecated because it doesn't affect MySQL Server." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Oracle MySQL Server is prone to multiple vulnerabilities.

  For further information refer to the official advisory via the referenced link." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.3 through 5.3.13 and 8.0 through 8.0.17." );
	script_tag( name: "solution", value: "Update to version 5.3.14, 8.0.18 or later." );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuoct2019.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpuoct2019" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

