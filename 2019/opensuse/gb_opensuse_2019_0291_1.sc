if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852329" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-30 13:15:00 +0000 (Tue, 30 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-03-05 04:08:32 +0100 (Tue, 05 Mar 2019)" );
	script_name( "openSUSE: Security Advisory for procps (openSUSE-SU-2019:0291-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:0291-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00003.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'procps'
  package(s) announced via the openSUSE-SU-2019:0291-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for procps fixes the following security issues:

  - CVE-2018-1122: Prevent local privilege escalation in top. If a user ran
  top with HOME unset in an attacker-controlled directory, the attacker
  could have achieved privilege escalation by exploiting one of several
  vulnerabilities in the config_file() function (bsc#1092100).

  - CVE-2018-1123: Prevent denial of service in ps via mmap buffer overflow.
  Inbuilt protection in ps mapped a guard page at the end of the overflowed
  buffer, ensuring that the impact of this flaw is limited to a crash
  (temporary denial of service) (bsc#1092100).

  - CVE-2018-1124: Prevent multiple integer overflows leading to a heap
  corruption in file2strvec function. This allowed a privilege escalation
  for a local attacker who can create entries in procfs by starting
  processes, which could result in crashes or arbitrary code execution in
  proc utilities run by
  other users (bsc#1092100).

  - CVE-2018-1125: Prevent stack buffer overflow in pgrep. This
  vulnerability was mitigated by FORTIFY limiting the impact to a crash
  (bsc#1092100).

  - CVE-2018-1126: Ensure correct integer size in proc/alloc.* to prevent
  truncation/integer overflow issues (bsc#1092100).

  (These issues were previously released for SUSE Linux Enterprise 12 SP3
  and SP4.)

  Also the following non-security issue was fixed:

  - Fix CPU summary showing old data. (bsc#1121753)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-291=1" );
	script_tag( name: "affected", value: "procps on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libprocps3", rpm: "libprocps3~3.3.9~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libprocps3-debuginfo", rpm: "libprocps3-debuginfo~3.3.9~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "procps", rpm: "procps~3.3.9~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "procps-debuginfo", rpm: "procps-debuginfo~3.3.9~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "procps-debugsource", rpm: "procps-debugsource~3.3.9~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "procps-devel", rpm: "procps-devel~3.3.9~23.1", rls: "openSUSELeap42.3" ) )){
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

