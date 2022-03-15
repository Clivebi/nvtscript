if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853343" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2020-10713", "CVE-2020-14308", "CVE-2020-14309", "CVE-2020-14310", "CVE-2020-14311", "CVE-2020-15706", "CVE-2020-15707" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)" );
	script_tag( name: "creation_date", value: "2020-08-09 03:00:41 +0000 (Sun, 09 Aug 2020)" );
	script_name( "openSUSE: Security Advisory for grub2 (openSUSE-SU-2020:1169-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1169-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00017.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'grub2'
  package(s) announced via the openSUSE-SU-2020:1169-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for grub2 fixes the following issues:

  - Fix for CVE-2020-10713 (bsc#1168994)

  - Fix for CVE-2020-14308 CVE-2020-14309, CVE-2020-14310, CVE-2020-14311
  (bsc#1173812)

  - Fix for CVE-2020-15706 (bsc#1174463)

  - Fix for CVE-2020-15707 (bsc#1174570)

  - Use overflow checking primitives where the arithmetic expression for
  buffer

  - Use grub_calloc for overflow check and return NULL when it would occur

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1169=1" );
	script_tag( name: "affected", value: "'grub2' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "grub2", rpm: "grub2~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-branding-upstream", rpm: "grub2-branding-upstream~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-debuginfo", rpm: "grub2-debuginfo~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-debugsource", rpm: "grub2-debugsource~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-i386-efi", rpm: "grub2-i386-efi~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-i386-efi-debug", rpm: "grub2-i386-efi-debug~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-i386-pc", rpm: "grub2-i386-pc~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-i386-pc-debug", rpm: "grub2-i386-pc-debug~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-i386-xen", rpm: "grub2-i386-xen~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-snapper-plugin", rpm: "grub2-snapper-plugin~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-systemd-sleep-plugin", rpm: "grub2-systemd-sleep-plugin~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-x86_64-efi", rpm: "grub2-x86_64-efi~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-x86_64-efi-debug", rpm: "grub2-x86_64-efi-debug~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-x86_64-xen", rpm: "grub2-x86_64-xen~2.04~lp152.7.3.4", rls: "openSUSELeap15.2" ) )){
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

