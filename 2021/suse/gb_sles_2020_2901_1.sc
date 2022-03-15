if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2901.1" );
	script_cve_id( "CVE-2020-25219", "CVE-2020-26154" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-29 04:15:00 +0000 (Sun, 29 Nov 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2901-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1|SLES15\\.0SP2|SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2901-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202901-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libproxy' package(s) announced via the SUSE-SU-2020:2901-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libproxy fixes the following issues:

CVE-2020-25219: Rewrote url::recvline to be nonrecursive (bsc#1176410).

CVE-2020-26154: Fixed a buffer overflow when PAC is enabled
 (bsc#1177143)." );
	script_tag( name: "affected", value: "'libproxy' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Workstation Extension 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP2." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libproxy-debugsource", rpm: "libproxy-debugsource~0.4.15~4.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy-devel", rpm: "libproxy-devel~0.4.15~4.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy1", rpm: "libproxy1~0.4.15~4.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy1-debuginfo", rpm: "libproxy1-debuginfo~0.4.15~4.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy-plugins-debugsource", rpm: "libproxy-plugins-debugsource~0.4.15~4.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Net-Libproxy", rpm: "perl-Net-Libproxy~0.4.15~4.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Net-Libproxy-debuginfo", rpm: "perl-Net-Libproxy-debuginfo~0.4.15~4.3.1", rls: "SLES15.0SP1" ) )){
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libproxy-debugsource", rpm: "libproxy-debugsource~0.4.15~4.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy-devel", rpm: "libproxy-devel~0.4.15~4.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy1", rpm: "libproxy1~0.4.15~4.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy1-debuginfo", rpm: "libproxy1-debuginfo~0.4.15~4.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy-plugins-debugsource", rpm: "libproxy-plugins-debugsource~0.4.15~4.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Net-Libproxy", rpm: "perl-Net-Libproxy~0.4.15~4.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Net-Libproxy-debuginfo", rpm: "perl-Net-Libproxy-debuginfo~0.4.15~4.3.1", rls: "SLES15.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libproxy-debugsource", rpm: "libproxy-debugsource~0.4.15~4.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy-devel", rpm: "libproxy-devel~0.4.15~4.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy-plugins-debugsource", rpm: "libproxy-plugins-debugsource~0.4.15~4.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy1", rpm: "libproxy1~0.4.15~4.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libproxy1-debuginfo", rpm: "libproxy1-debuginfo~0.4.15~4.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Net-Libproxy", rpm: "perl-Net-Libproxy~0.4.15~4.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Net-Libproxy-debuginfo", rpm: "perl-Net-Libproxy-debuginfo~0.4.15~4.3.1", rls: "SLES15.0" ) )){
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

