if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878055" );
	script_version( "2021-07-16T02:00:53+0000" );
	script_cve_id( "CVE-2019-18348", "CVE-2020-8492" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-16 02:00:53 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-15 12:15:00 +0000 (Wed, 15 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-12 03:19:21 +0000 (Sun, 12 Jul 2020)" );
	script_name( "Fedora: Security Advisory for python36 (FEDORA-2020-ea5bdbcc90)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-ea5bdbcc90" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/A5NSAX4SC3V64PGZUPH7PRDLSON34Q5A" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python36'
  package(s) announced via the FEDORA-2020-ea5bdbcc90 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python 3.6 package for developers.

This package exists to allow developers to test their code against an older
version of Python. This is not a full Python stack and if you wish to run
your applications with Python 3.6, see other distributions
that support it, such as CentOS or RHEL with Software Collections
or older Fedora releases." );
	script_tag( name: "affected", value: "'python36' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "python36", rpm: "python36~3.6.11~1.fc31", rls: "FC31" ) )){
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

