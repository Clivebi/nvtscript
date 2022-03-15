if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851803" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-30 05:50:52 +0200 (Sat, 30 Jun 2018)" );
	script_cve_id( "CVE-2018-7409", "CVE-2018-7485" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 15:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for unixODBC (openSUSE-SU-2018:1845-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'unixODBC'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for unixODBC to version 2.3.6
  fixes the following issues:

  - CVE-2018-7409: Buffer overflow in unicode_to_ansi_copy() was fixed in
  2.3.5 (bsc#1082290)

  - CVE-2018-7485: Swapped arguments in SQLWriteFileDSN() in
  odbcinst/SQLWriteFileDSN.c (bsc#1082484)

  Other fixes:

  - Enabled --enable-fastvalidate option in configure (bsc#1044970)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-684=1" );
	script_tag( name: "affected", value: "unixODBC on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:1845-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00050.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
	if(!isnull( res = isrpmvuln( pkg: "unixODBC", rpm: "unixODBC~2.3.6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unixODBC-debuginfo", rpm: "unixODBC-debuginfo~2.3.6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unixODBC-debugsource", rpm: "unixODBC-debugsource~2.3.6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unixODBC-devel", rpm: "unixODBC-devel~2.3.6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unixODBC-32bit", rpm: "unixODBC-32bit~2.3.6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unixODBC-debuginfo-32bit", rpm: "unixODBC-debuginfo-32bit~2.3.6~8.1", rls: "openSUSELeap42.3" ) )){
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

