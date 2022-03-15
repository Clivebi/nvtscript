if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883295" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2020-17507" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 18:15:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-11-19 04:01:20 +0000 (Thu, 19 Nov 2020)" );
	script_name( "CentOS: Security Advisory for qt5-qtbase (CESA-2020:5021)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:5021" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-November/035826.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qt5-qtbase'
  package(s) announced via the CESA-2020:5021 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The qt packages contain a software toolkit that simplifies the task of
writing and maintaining Graphical User Interface (GUI) applications for the
X Window System.

Qt is a software toolkit for developing applications. The qt5-base packages
contain base tools for string, xml, and network handling in Qt.

Security Fix(es):

  * qt: buffer over-read in read_xbm_body in gui/image/qxbmhandler.cpp
(CVE-2020-17507)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'qt5-qtbase' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase", rpm: "qt5-qtbase~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase-common", rpm: "qt5-qtbase-common~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase-devel", rpm: "qt5-qtbase-devel~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase-doc", rpm: "qt5-qtbase-doc~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase-examples", rpm: "qt5-qtbase-examples~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase-gui", rpm: "qt5-qtbase-gui~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase-mysql", rpm: "qt5-qtbase-mysql~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase-odbc", rpm: "qt5-qtbase-odbc~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase-postgresql", rpm: "qt5-qtbase-postgresql~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtbase-static", rpm: "qt5-qtbase-static~5.9.7~5.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt5-rpm-macros", rpm: "qt5-rpm-macros~5.9.7~5.el7_9", rls: "CentOS7" ) )){
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

