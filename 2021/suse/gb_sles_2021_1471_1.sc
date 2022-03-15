if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1471.1" );
	script_cve_id( "CVE-2021-25214", "CVE-2021-25215" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:39 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 09:15:00 +0000 (Fri, 21 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1471-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1471-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211471-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2021:1471-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bind fixes the following issues:

CVE-2021-25214: Fixed a broken inbound incremental zone update (IXFR)
 which could have caused named to terminate unexpectedly (bsc#1185345).

CVE-2021-25215: Fixed an assertion check which could have failed while
 answering queries for DNAME records that required the DNAME to be
 processed to resolve itself (bsc#1185345).

make /usr/bin/delv in bind-tools position independent (bsc#1183453)." );
	script_tag( name: "affected", value: "'bind' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP2, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils-debuginfo", rpm: "bind-utils-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbind9-1600", rpm: "libbind9-1600~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbind9-1600-debuginfo", rpm: "libbind9-1600-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns1605", rpm: "libdns1605~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns1605-debuginfo", rpm: "libdns1605-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs-devel", rpm: "libirs-devel~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs1601", rpm: "libirs1601~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs1601-debuginfo", rpm: "libirs1601-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc1606", rpm: "libisc1606~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc1606-debuginfo", rpm: "libisc1606-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccc1600", rpm: "libisccc1600~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccc1600-debuginfo", rpm: "libisccc1600-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccfg1600", rpm: "libisccfg1600~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccfg1600-debuginfo", rpm: "libisccfg1600-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libns1604", rpm: "libns1604~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libns1604-debuginfo", rpm: "libns1604-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-bind", rpm: "python3-bind~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.16.6~12.49.1", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils-debuginfo", rpm: "bind-utils-debuginfo~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbind9-1600", rpm: "libbind9-1600~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbind9-1600-debuginfo", rpm: "libbind9-1600-debuginfo~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns1605", rpm: "libdns1605~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns1605-debuginfo", rpm: "libdns1605-debuginfo~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs-devel", rpm: "libirs-devel~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs1601", rpm: "libirs1601~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs1601-debuginfo", rpm: "libirs1601-debuginfo~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc1606", rpm: "libisc1606~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc1606-debuginfo", rpm: "libisc1606-debuginfo~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccc1600", rpm: "libisccc1600~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccc1600-debuginfo", rpm: "libisccc1600-debuginfo~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccfg1600", rpm: "libisccfg1600~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccfg1600-debuginfo", rpm: "libisccfg1600-debuginfo~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libns1604", rpm: "libns1604~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libns1604-debuginfo", rpm: "libns1604-debuginfo~9.16.6~12.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-bind", rpm: "python3-bind~9.16.6~12.49.1", rls: "SLES15.0" ) )){
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils-debuginfo", rpm: "bind-utils-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbind9-1600", rpm: "libbind9-1600~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbind9-1600-debuginfo", rpm: "libbind9-1600-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns1605", rpm: "libdns1605~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns1605-debuginfo", rpm: "libdns1605-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs-devel", rpm: "libirs-devel~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs1601", rpm: "libirs1601~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs1601-debuginfo", rpm: "libirs1601-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc1606", rpm: "libisc1606~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc1606-debuginfo", rpm: "libisc1606-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccc1600", rpm: "libisccc1600~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccc1600-debuginfo", rpm: "libisccc1600-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccfg1600", rpm: "libisccfg1600~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccfg1600-debuginfo", rpm: "libisccfg1600-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libns1604", rpm: "libns1604~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libns1604-debuginfo", rpm: "libns1604-debuginfo~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-bind", rpm: "python3-bind~9.16.6~12.49.1", rls: "SLES15.0SP1" ) )){
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

