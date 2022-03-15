if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853012" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2019-12838", "CVE-2019-19727", "CVE-2019-19728" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-24 03:15:00 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2020-01-27 09:18:57 +0000 (Mon, 27 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for slurm (openSUSE-SU-2020:0085_1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0085-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00038.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'slurm'
  package(s) announced via the openSUSE-SU-2020:0085-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for slurm to version 18.08.9 fixes the following issues:

  Security issues fixed:

  - CVE-2019-19728: Fixed a privilege escalation with srun, where --uid
  might have unintended side effects (bsc#1159692).

  - CVE-2019-12838: Fixed SchedMD Slurm SQL Injection issue (bnc#1140709).

  - CVE-2019-19727: Fixed permissions of slurmdbd.conf (bsc#1155784).

  Bug fixes:

  - Fix ownership of /var/spool/slurm on new installations and upgrade
  (bsc#1158696).

  - Fix %posttrans macro _res_update to cope with added newline
  (bsc#1153259).

  - Move srun from 'slurm' to 'slurm-node': srun is required on the nodes as
  well so sbatch will work. 'slurm-node' is a requirement when 'slurm' is
  installed (bsc#1153095).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-85=1" );
	script_tag( name: "affected", value: "'slurm' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "libpmi0", rpm: "libpmi0~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpmi0-debuginfo", rpm: "libpmi0-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libslurm33", rpm: "libslurm33~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libslurm33-debuginfo", rpm: "libslurm33-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-slurm", rpm: "perl-slurm~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-slurm-debuginfo", rpm: "perl-slurm-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm", rpm: "slurm~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-auth-none", rpm: "slurm-auth-none~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-auth-none-debuginfo", rpm: "slurm-auth-none-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-config", rpm: "slurm-config~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-config-man", rpm: "slurm-config-man~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-cray", rpm: "slurm-cray~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-cray-debuginfo", rpm: "slurm-cray-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-debuginfo", rpm: "slurm-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-debugsource", rpm: "slurm-debugsource~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-devel", rpm: "slurm-devel~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-doc", rpm: "slurm-doc~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-hdf5", rpm: "slurm-hdf5~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-hdf5-debuginfo", rpm: "slurm-hdf5-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-lua", rpm: "slurm-lua~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-lua-debuginfo", rpm: "slurm-lua-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-munge", rpm: "slurm-munge~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-munge-debuginfo", rpm: "slurm-munge-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-node", rpm: "slurm-node~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-node-debuginfo", rpm: "slurm-node-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-openlava", rpm: "slurm-openlava~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-pam_slurm", rpm: "slurm-pam_slurm~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-pam_slurm-debuginfo", rpm: "slurm-pam_slurm-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-plugins", rpm: "slurm-plugins~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-plugins-debuginfo", rpm: "slurm-plugins-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-seff", rpm: "slurm-seff~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-sjstat", rpm: "slurm-sjstat~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-slurmdbd", rpm: "slurm-slurmdbd~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-slurmdbd-debuginfo", rpm: "slurm-slurmdbd-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-sql", rpm: "slurm-sql~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-sql-debuginfo", rpm: "slurm-sql-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-sview", rpm: "slurm-sview~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-sview-debuginfo", rpm: "slurm-sview-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-torque", rpm: "slurm-torque~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-torque-debuginfo", rpm: "slurm-torque-debuginfo~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slurm-webdoc", rpm: "slurm-webdoc~18.08.9~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
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

