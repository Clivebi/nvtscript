if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0109.1" );
	script_cve_id( "CVE-2017-9271" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:45 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 17:16:00 +0000 (Thu, 25 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0109-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0109-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210109-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libzypp, zypper' package(s) announced via the SUSE-SU-2021:0109-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libzypp, zypper fixes the following issues:

Update zypper to version 1.14.41

Update libzypp to 17.25.4

CVE-2017-9271: Fixed information leak in the log file (bsc#1050625
 bsc#1177583)

RepoManager: Force refresh if repo url has changed (bsc#1174016)

RepoManager: Carefully tidy up the caches. Remove non-directory entries.
 (bsc#1178966)

RepoInfo: ignore legacy type= in a .repo file and let RepoManager probe
 (bsc#1177427).

RpmDb: If no database exists use the _dbpath configured in rpm. Still
 makes sure a compat symlink at /var/lib/rpm exists in case the
 configures _dbpath is elsewhere. (bsc#1178910)

Fixed update of gpg keys with elongated expire date (bsc#179222)

needreboot: remove udev from the list (bsc#1179083)

Fix lsof monitoring (bsc#1179909)

yast-installation was updated to 4.2.48:

Do not cleanup the libzypp cache when the system has low memory,
 incomplete cache confuses libzypp later (bsc#1179415)" );
	script_tag( name: "affected", value: "'libzypp, zypper' package(s) on SUSE Linux Enterprise Installer 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libzypp", rpm: "libzypp~17.25.5~3.25.6", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debuginfo", rpm: "libzypp-debuginfo~17.25.5~3.25.6", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debugsource", rpm: "libzypp-debugsource~17.25.5~3.25.6", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-devel", rpm: "libzypp-devel~17.25.5~3.25.6", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "yast2-installation", rpm: "yast2-installation~4.2.48~3.16.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper", rpm: "zypper~1.14.41~3.14.10", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-debuginfo", rpm: "zypper-debuginfo~1.14.41~3.14.10", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-debugsource", rpm: "zypper-debugsource~1.14.41~3.14.10", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-log", rpm: "zypper-log~1.14.41~3.14.10", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-needs-restarting", rpm: "zypper-needs-restarting~1.14.41~3.14.10", rls: "SLES15.0SP2" ) )){
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

