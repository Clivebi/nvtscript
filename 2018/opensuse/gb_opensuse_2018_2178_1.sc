if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851831" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-04 05:46:47 +0200 (Sat, 04 Aug 2018)" );
	script_cve_id( "CVE-2018-0495" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for libgcrypt (openSUSE-SU-2018:2178-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgcrypt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libgcrypt fixes the following issues:

  The following security vulnerability was addressed:

  - CVE-2018-0495: Mitigate a novel side-channel attack by enabling blinding
  for ECDSA signatures (bsc#1097410).

  The following other issues were fixed:

  - Extended the fipsdrv dsa-sign and dsa-verify commands with the

  - -algo parameter for the FIPS testing of DSA SigVer and SigGen
  (bsc#1064455).

  - Ensure libgcrypt20-hmac and libgcrypt20 are installed in the correct
  order. (bsc#1090766)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-795=1" );
	script_tag( name: "affected", value: "libgcrypt on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2178-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00002.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-cavs", rpm: "libgcrypt-cavs~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-cavs-debuginfo", rpm: "libgcrypt-cavs-debuginfo~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-debugsource", rpm: "libgcrypt-debugsource~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel", rpm: "libgcrypt-devel~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel-debuginfo", rpm: "libgcrypt-devel-debuginfo~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20", rpm: "libgcrypt20~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-debuginfo", rpm: "libgcrypt20-debuginfo~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-hmac", rpm: "libgcrypt20-hmac~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel-32bit", rpm: "libgcrypt-devel-32bit~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel-debuginfo-32bit", rpm: "libgcrypt-devel-debuginfo-32bit~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-32bit", rpm: "libgcrypt20-32bit~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-debuginfo-32bit", rpm: "libgcrypt20-debuginfo-32bit~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-hmac-32bit", rpm: "libgcrypt20-hmac-32bit~1.6.1~45.1", rls: "openSUSELeap42.3" ) )){
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

