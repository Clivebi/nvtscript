if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853930" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2020-13950", "CVE-2020-35452", "CVE-2021-26690", "CVE-2021-26691", "CVE-2021-30641", "CVE-2021-31618" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:03:36 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for apache2 (openSUSE-SU-2021:2127-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2127-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KAQGPGA6ZQQT3VO5WOYFSSTZFH57MPWK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2'
  package(s) announced via the openSUSE-SU-2021:2127-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for apache2 fixes the following issues:

  - fixed CVE-2021-30641 [bsc#1187174]: MergeSlashes regression

  - fixed CVE-2021-31618 [bsc#1186924]: NULL pointer dereference on
       specially crafted HTTP/2 request

  - fixed CVE-2020-13950 [bsc#1187040]: mod_proxy NULL pointer dereference

  - fixed CVE-2020-35452 [bsc#1186922]: Single zero byte stack overflow in
       mod_auth_digest

  - fixed CVE-2021-26690 [bsc#1186923]: mod_session NULL pointer dereference
       in parser

  - fixed CVE-2021-26691 [bsc#1187017]: Heap overflow in mod_session" );
	script_tag( name: "affected", value: "'apache2' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "apache2", rpm: "apache2~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-debuginfo", rpm: "apache2-debuginfo~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-debugsource", rpm: "apache2-debugsource~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-devel", rpm: "apache2-devel~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-event", rpm: "apache2-event~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-event-debuginfo", rpm: "apache2-event-debuginfo~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-pages", rpm: "apache2-example-pages~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork", rpm: "apache2-prefork~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork-debuginfo", rpm: "apache2-prefork-debuginfo~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils", rpm: "apache2-utils~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils-debuginfo", rpm: "apache2-utils-debuginfo~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker", rpm: "apache2-worker~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker-debuginfo", rpm: "apache2-worker-debuginfo~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-doc", rpm: "apache2-doc~2.4.43~3.22.1", rls: "openSUSELeap15.3" ) )){
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
