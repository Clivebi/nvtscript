if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113100" );
	script_version( "2021-09-20T15:26:26+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 15:26:26 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-02-02 11:11:11 +0100 (Fri, 02 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-2297", "CVE-2017-2293" );
	script_name( "Puppet Enterprise < 2016.4.4 / 2017 < 2017.2.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "summary", value: "Versions of Puppet Enterprise prior to 2016.4.5 or 2017.2.1 are prone to multiple vulnerabilities.

  This NVT has duplicated the existing NVT 'Puppet Enterprise < 2016.4.5 / < 2017.2.1 Multiple Vulnerabilities' (OID: 1.3.6.1.4.1.25623.1.0.106929)." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The affected versions shipped with an MCollective configuration that allowed the package plugin to install or remove arbitrary packages on all managed agents.

  The affected versions did not correctly authenticate users before returning labeled RBAC access tokens" );
	script_tag( name: "affected", value: "Puppet Enterprise through 2016.4.4 or 2017.2.0" );
	script_tag( name: "solution", value: "Update to version 2016.4.5 or 2017.2.1 respectively." );
	script_xref( name: "URL", value: "https://puppet.com/security/cve/cve-2017-2293" );
	script_xref( name: "URL", value: "https://puppet.com/security/cve/cve-2017-2297" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

