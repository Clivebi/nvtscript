if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883071" );
	script_version( "2021-08-27T14:01:18+0000" );
	script_cve_id( "CVE-2019-10160", "CVE-2019-9636" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-27 14:01:18 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-06 16:11:00 +0000 (Wed, 06 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-06-25 02:00:40 +0000 (Tue, 25 Jun 2019)" );
	script_name( "CentOS Update for python CESA-2019:1587 centos7 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:1587" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-June/023337.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python'
  package(s) announced via the CESA-2019:1587 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python is an interpreted, interactive, object-oriented programming
language, which includes modules, classes, exceptions, very high level
dynamic data types and dynamic typing. Python supports interfaces to many
system calls and libraries, as well as to various windowing systems.

Security Fix(es):

  * python: regression of CVE-2019-9636 due to functional fix to allow port
numbers in netloc (CVE-2019-10160)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'python' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.7.5~80.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debug", rpm: "python-debug~2.7.5~80.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.5~80.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libs", rpm: "python-libs~2.7.5~80.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-test", rpm: "python-test~2.7.5~80.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tools", rpm: "python-tools~2.7.5~80.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tkinter", rpm: "tkinter~2.7.5~80.el7_6", rls: "CentOS7" ) )){
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

