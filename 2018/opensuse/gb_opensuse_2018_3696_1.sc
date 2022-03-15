if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852111" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_cve_id( "CVE-2017-0358" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-11-10 05:57:36 +0100 (Sat, 10 Nov 2018)" );
	script_name( "openSUSE: Security Advisory for ntfs-3g_ntfsprogs (openSUSE-SU-2018:3696-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2018:3696-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00008.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntfs-3g_ntfsprogs'
  package(s) announced via the openSUSE-SU-2018:3696-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ntfs-3g_ntfsprogs fixes the following issues:

  - CVE-2017-0358: Missing sanitization of the environment during a call to
  modprobe allowed local users to escalate for root privilege (bsc#1022500)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1376=1" );
	script_tag( name: "affected", value: "ntfs-3g_ntfsprogs on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libntfs-3g-devel", rpm: "libntfs-3g-devel~2013.1.13~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libntfs-3g84", rpm: "libntfs-3g84~2013.1.13~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libntfs-3g84-debuginfo", rpm: "libntfs-3g84-debuginfo~2013.1.13~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfs-3g", rpm: "ntfs-3g~2013.1.13~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfs-3g-debuginfo", rpm: "ntfs-3g-debuginfo~2013.1.13~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfs-3g_ntfsprogs-debugsource", rpm: "ntfs-3g_ntfsprogs-debugsource~2013.1.13~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfsprogs", rpm: "ntfsprogs~2013.1.13~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntfsprogs-debuginfo", rpm: "ntfsprogs-debuginfo~2013.1.13~7.3.1", rls: "openSUSELeap42.3" ) )){
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

