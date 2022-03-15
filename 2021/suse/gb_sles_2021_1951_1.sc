if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1951.1" );
	script_cve_id( "CVE-2021-31607" );
	script_tag( name: "creation_date", value: "2021-06-11 02:15:39 +0000 (Fri, 11 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-04 20:24:00 +0000 (Tue, 04 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1951-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1951-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211951-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'salt' package(s) announced via the SUSE-SU-2021:1951-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for salt fixes the following issues:

Check if dpkgnotify is executable (bsc#1186674)

Update to Salt release version 3002.2 (jsc#ECO-3212, jsc#SLE-18033,
 jsc#SLE-18028)

Drop support for Python2. Obsoletes `python2-salt` package
 (jsc#SLE-18028)

Fix issue parsing errors in ansiblegate state module

Prevent command injection in the snapper module (bsc#1185281,
 CVE-2021-31607)

transactional_update: detect recursion in the executor

Add subpackage `salt-transactional-update` (jsc#SLE-18033)

Remove duplicate directories" );
	script_tag( name: "affected", value: "'salt' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Server Applications 15-SP3, SUSE Linux Enterprise Module for Transactional Server 15-SP3." );
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "python3-salt", rpm: "python3-salt~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt", rpm: "salt~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-bash-completion", rpm: "salt-bash-completion~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-doc", rpm: "salt-doc~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-minion", rpm: "salt-minion~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-zsh-completion", rpm: "salt-zsh-completion~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-api", rpm: "salt-api~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-cloud", rpm: "salt-cloud~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-fish-completion", rpm: "salt-fish-completion~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-master", rpm: "salt-master~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-proxy", rpm: "salt-proxy~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-ssh", rpm: "salt-ssh~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-standalone-formulas-configuration", rpm: "salt-standalone-formulas-configuration~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-syndic", rpm: "salt-syndic~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-transactional-update", rpm: "salt-transactional-update~3002.2~8.41.8.1", rls: "SLES15.0SP3" ) )){
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

