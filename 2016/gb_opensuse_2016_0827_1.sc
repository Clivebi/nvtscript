if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851255" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-03-20 06:18:16 +0100 (Sun, 20 Mar 2016)" );
	script_cve_id( "CVE-2016-1285", "CVE-2016-1286" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for bind (openSUSE-SU-2016:0827-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bind fixes the following issues:

  * CVE-2016-1285: remote DoS caused by malformed data on control channel

  * CVE-2016-1286: remote DoS via assertion failure in parsing of signature
  records for DNAME records" );
	script_tag( name: "affected", value: "bind on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0827-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.1" );
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
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo", rpm: "bind-libs-debuginfo~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-lwresd", rpm: "bind-lwresd~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-lwresd-debuginfo", rpm: "bind-lwresd-debuginfo~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils-debuginfo", rpm: "bind-utils-debuginfo~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-32bit", rpm: "bind-libs-32bit~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo-32bit", rpm: "bind-libs-debuginfo-32bit~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.9.4P2~2.29.1", rls: "openSUSE13.1" ) )){
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

