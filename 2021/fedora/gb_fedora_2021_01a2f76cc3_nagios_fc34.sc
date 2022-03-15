if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879122" );
	script_version( "2021-08-23T14:00:58+0000" );
	script_cve_id( "CVE-2020-13977" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 14:00:58 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-24 23:09:00 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-20 04:06:57 +0000 (Sat, 20 Mar 2021)" );
	script_name( "Fedora: Security Advisory for nagios (FEDORA-2021-01a2f76cc3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-01a2f76cc3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5P6NHNG2SJAM6DXVTXQH3AOJ4WQVKJUE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nagios'
  package(s) announced via the FEDORA-2021-01a2f76cc3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Nagios is a program that will monitor hosts and services on your
network.  It has the ability to send email or page alerts when a
problem arises and when a problem is resolved.  Nagios is written
in C and is designed to run under Linux (and some other *NIX
variants) as a background process, intermittently running checks
on various services that you specify.

The actual service checks are performed by separate 'plugin' programs
which return the status of the checks to Nagios.

This package provides the core program, web interface, and documentation
files for Nagios. Development files are built as a separate package." );
	script_tag( name: "affected", value: "'nagios' package(s) on Fedora 34." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "nagios", rpm: "nagios~4.4.6~4.fc34", rls: "FC34" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

