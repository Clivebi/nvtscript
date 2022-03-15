if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113101" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-02-02 11:40:38 +0100 (Fri, 02 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-24 16:29:00 +0000 (Sat, 24 Feb 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-2296" );
	script_name( "Puppet Enterprise 2017 < 2017.2.2 Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "summary", value: "Puppet Enterprise before 2017.2.2 is prone to a Denial of Service Vulnerability.

  This NVT has duplicated the existing NVT 'Puppet Enterprise 2017 < 2017.2.2 DoS Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.106930)." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "In the affected versions, using specially formatted strings with certain formatting characters as Classifier node group names or RBAC role display names causes errors, effectively causing a DoS to the service." );
	script_tag( name: "affected", value: "Puppet Enterprise from 2017.1.0 through 2017.2.1" );
	script_tag( name: "solution", value: "Update to 2017.2.2" );
	script_xref( name: "URL", value: "https://puppet.com/security/cve/cve-2017-2296" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

