if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107229" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-28 17:33:05 +0200 (Wed, 28 Jun 2017)" );
	script_cve_id( "CVE-2017-6334" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NETGEAR DGN2200 CVE-2017-6334 Remote Code Execution Vulnerability" );
	script_tag( name: "summary", value: "NETGEAR DGN2200 is prone to a remote code-execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code within the context of the affected application. Failed exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "NETGEAR DGN2200 v1, v2, v3, v4" );
	script_tag( name: "solution", value: "Update the Firmware, for more details" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/96463" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "deprecated", value: TRUE );
	script_xref( name: "URL", value: "https://kb.netgear.com/000037343/Security-Advisory-for-Remote-Command-Execution-and-CSRF-Vulnerabilities-on-DGN2200" );
	exit( 0 );
}
exit( 66 );

