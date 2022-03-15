if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0956.1" );
	script_cve_id( "CVE-2017-9271" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-31T02:24:17+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 02:24:17 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 17:16:00 +0000 (Thu, 25 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0956-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0956-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210956-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libzypp, zypper' package(s) announced via the SUSE-SU-2021:0956-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libzypp, zypper fixes the following issues:

Update zypper to version 1.14.43:

doc: give more details about creating versioned package locks
 (bsc#1181622)

man: Document synonymously used patch categories (bsc#1179847)

Fix source-download commands help (bsc#1180663)

man: Recommend to use the --non-interactive global option rather than
 the command option -y (bsc#1179816)

Extend apt packagemap (fixes #366)

--quiet: Fix install summary to write nothing if there's nothing todo
 (bsc#1180077)

Prefer /run over /var/run.

Update libzypp to 17.25.8:

Try to provide a mounted /proc in --root installs (bsc#1181328) Some
 systemd tools require /proc to be mounted and fail if it's not there.

Enable release packages to request a releaxed suse/opensuse vendorcheck
 in dup when migrating. (bsc#1182629)

Patch: Identify well-known category names (bsc#1179847) This allows to
 use the RH and SUSE patch categrory names synonymously: (recommended =
 bugfix) and (optional = feature = enhancement).

Add missing includes for GCC 11 compatibility.

Fix %posttrans script execution (fixes #265) The scripts are execuable.
 No need to call them through 'sh -c'.

Commit: Fix rpmdb compat symlink in case rpm got removed.

Repo: Allow multiple baseurls specified on one line (fixes #285)

Regex: Fix memory leak and undefined behavior.

Add rpm buildrequires for test suite (fixes #279)

Use rpmdb2solv new -D switch to tell the location ob the rpmdatabase to
 use.

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

Fixed update of gpg keys with elongated expire date (bsc#1179222)

needreboot: remove udev from the list (bsc#1179083)

Fix lsof monitoring (bsc#1179909)

Rephrase solver problem descriptions (jsc#SLE-8482)

Adapt to changed gpg2/libgpgme behavior (bsc#1180721)

Multicurl backend breaks with unknown filesize (fixes #277)" );
	script_tag( name: "affected", value: "'libzypp, zypper' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Installer 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libsigc++2-debugsource", rpm: "libsigc++2-debugsource~2.10.0~3.7.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsigc++2-devel", rpm: "libsigc++2-devel~2.10.0~3.7.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsigc-2_0-0", rpm: "libsigc-2_0-0~2.10.0~3.7.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsigc-2_0-0-debuginfo", rpm: "libsigc-2_0-0-debuginfo~2.10.0~3.7.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-debuginfo", rpm: "libsolv-debuginfo~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-debugsource", rpm: "libsolv-debugsource~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-devel", rpm: "libsolv-devel~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-devel-debuginfo", rpm: "libsolv-devel-debuginfo~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-tools", rpm: "libsolv-tools~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-tools-debuginfo", rpm: "libsolv-tools-debuginfo~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-ncurses-pkg-debugsource", rpm: "libyui-ncurses-pkg-debugsource~2.48.9~7.7.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-ncurses-pkg-devel", rpm: "libyui-ncurses-pkg-devel~2.48.9~7.7.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-ncurses-pkg-doc", rpm: "libyui-ncurses-pkg-doc~2.48.9~7.7.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-ncurses-pkg9", rpm: "libyui-ncurses-pkg9~2.48.9~7.7.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-ncurses-pkg9-debuginfo", rpm: "libyui-ncurses-pkg9-debuginfo~2.48.9~7.7.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-qt-pkg-debugsource", rpm: "libyui-qt-pkg-debugsource~2.45.28~3.10.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-qt-pkg-devel", rpm: "libyui-qt-pkg-devel~2.45.28~3.10.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-qt-pkg-doc", rpm: "libyui-qt-pkg-doc~2.45.28~3.10.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-qt-pkg9", rpm: "libyui-qt-pkg9~2.45.28~3.10.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libyui-qt-pkg9-debuginfo", rpm: "libyui-qt-pkg9-debuginfo~2.45.28~3.10.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp", rpm: "libzypp~17.25.8~3.48.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debuginfo", rpm: "libzypp-debuginfo~17.25.8~3.48.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debugsource", rpm: "libzypp-debugsource~17.25.8~3.48.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-devel", rpm: "libzypp-devel~17.25.8~3.48.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-solv", rpm: "perl-solv~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-solv-debuginfo", rpm: "perl-solv-debuginfo~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-solv", rpm: "python3-solv~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-solv-debuginfo", rpm: "python3-solv-debuginfo~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-solv", rpm: "ruby-solv~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-solv-debuginfo", rpm: "ruby-solv-debuginfo~0.7.17~3.32.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "yast2-pkg-bindings", rpm: "yast2-pkg-bindings~4.1.3~3.10.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "yast2-pkg-bindings-debuginfo", rpm: "yast2-pkg-bindings-debuginfo~4.1.3~3.10.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "yast2-pkg-bindings-debugsource", rpm: "yast2-pkg-bindings-debugsource~4.1.3~3.10.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper", rpm: "zypper~1.14.43~3.34.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-debuginfo", rpm: "zypper-debuginfo~1.14.43~3.34.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-debugsource", rpm: "zypper-debugsource~1.14.43~3.34.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-log", rpm: "zypper-log~1.14.43~3.34.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-needs-restarting", rpm: "zypper-needs-restarting~1.14.43~3.34.1", rls: "SLES15.0SP1" ) )){
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

