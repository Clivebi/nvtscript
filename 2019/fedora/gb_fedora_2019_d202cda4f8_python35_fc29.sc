if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876976" );
	script_version( "2021-09-02T12:01:30+0000" );
	script_cve_id( "CVE-2019-9740", "CVE-2019-10160", "CVE-2019-16935", "CVE-2019-18348", "CVE-2019-16056", "CVE-2018-14647", "CVE-2019-9636" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-02 12:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-06 16:11:00 +0000 (Wed, 06 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-11-10 03:24:25 +0000 (Sun, 10 Nov 2019)" );
	script_name( "Fedora Update for python35 FEDORA-2019-d202cda4f8" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-d202cda4f8" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JCPGLTTOBB3QEARDX4JOYURP6ELNNA2V" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python35'
  package(s) announced via the FEDORA-2019-d202cda4f8 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python 3.5 package for developers.

This package exists to allow developers to test their code against an older
version of Python. This is not a full Python stack and if you wish to run
your applications with Python 3.5, see other distributions
that support it, such as CentOS or RHEL with Software Collections
or older Fedora releases." );
	script_tag( name: "affected", value: "'python35' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "python35", rpm: "python35~3.5.8~2.fc29", rls: "FC29" ) )){
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

