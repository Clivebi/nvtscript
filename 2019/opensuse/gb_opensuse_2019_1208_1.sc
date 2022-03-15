if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852425" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2019-1787", "CVE-2019-1788", "CVE-2019-1789" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-07 15:55:00 +0000 (Thu, 07 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-04-17 02:01:02 +0000 (Wed, 17 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for clamav (openSUSE-SU-2019:1208-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1208-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00064.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the openSUSE-SU-2019:1208-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for clamav to version 0.100.3 fixes the following issues:

  Security issues fixed (bsc#1130721):

  - CVE-2019-1787: Fixed an out-of-bounds heap read condition which may
  occur when scanning PDF documents.

  - CVE-2019-1789: Fixed an out-of-bounds heap read condition which may
  occur when scanning PE files (i.e. Windows EXE and DLL files).

  - CVE-2019-1788: Fixed an out-of-bounds heap write condition which may
  occur when scanning OLE2 files such as Microsoft Office 97-2003
  documents.

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1208=1" );
	script_tag( name: "affected", value: "'clamav' package(s) on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.100.3~35.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-debuginfo", rpm: "clamav-debuginfo~0.100.3~35.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-debugsource", rpm: "clamav-debugsource~0.100.3~35.1", rls: "openSUSELeap42.3" ) )){
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

