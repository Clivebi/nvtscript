if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878307" );
	script_version( "2020-09-18T13:18:38+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-09-18 13:18:38 +0000 (Fri, 18 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-17 03:08:01 +0000 (Thu, 17 Sep 2020)" );
	script_name( "Fedora: Security Advisory for python35 (FEDORA-2020-4cf7c3910b)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-4cf7c3910b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QFO3MHXI4AF6R64TNQT5H6IE5FCCG3AL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python35'
  package(s) announced via the FEDORA-2020-4cf7c3910b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python 3.5 package for developers.

This package exists to allow developers to test their code against an older
version of Python. This is not a full Python stack and if you wish to run
your applications with Python 3.5, see other distributions
that support it, such as CentOS or RHEL with Software Collections
or older Fedora releases." );
	script_tag( name: "affected", value: "'python35' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "python35", rpm: "python35~3.5.10~1.fc31", rls: "FC31" ) )){
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

