if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852668" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2017-14988" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-23 20:15:00 +0000 (Mon, 23 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-08-20 02:00:57 +0000 (Tue, 20 Aug 2019)" );
	script_name( "openSUSE: Security Advisory for openexr (openSUSE-SU-2019:1954-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1954-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00063.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openexr'
  package(s) announced via the openSUSE-SU-2019:1954-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openexr fixes the following issues:

  - CVE-2017-14988: Fixed a denial of service in Header::readfrom()
  (bsc#1061305).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1954=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1954=1" );
	script_tag( name: "affected", value: "'openexr' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23", rpm: "libIlmImf-2_2-23~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23-debuginfo", rpm: "libIlmImf-2_2-23-debuginfo~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23", rpm: "libIlmImfUtil-2_2-23~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23-debuginfo", rpm: "libIlmImfUtil-2_2-23-debuginfo~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr", rpm: "openexr~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debuginfo", rpm: "openexr-debuginfo~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debugsource", rpm: "openexr-debugsource~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-devel", rpm: "openexr-devel~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-doc", rpm: "openexr-doc~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23-32bit", rpm: "libIlmImf-2_2-23-32bit~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23-32bit-debuginfo", rpm: "libIlmImf-2_2-23-32bit-debuginfo~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23-32bit", rpm: "libIlmImfUtil-2_2-23-32bit~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23-32bit-debuginfo", rpm: "libIlmImfUtil-2_2-23-32bit-debuginfo~2.2.1~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
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

