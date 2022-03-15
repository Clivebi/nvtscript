if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853651" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2021-3474", "CVE-2021-3475", "CVE-2021-3476" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-11 04:15:00 +0000 (Sun, 11 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:58:42 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for openexr (openSUSE-SU-2021:0536-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0536-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3OEPCGI23GJK5SW2WMNMPUTRJTU2STGG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openexr'
  package(s) announced via the openSUSE-SU-2021:0536-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openexr fixes the following issues:

  - CVE-2021-3474: Undefined-shift in
       Imf_2_5::FastHufDecoder::FastHufDecoder (bsc#1184174)

  - CVE-2021-3475: Integer-overflow in Imf_2_5::calculateNumTiles
       (bsc#1184173)

  - CVE-2021-3476: Undefined-shift in Imf_2_5::unpack14 (bsc#1184172)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'openexr' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23", rpm: "libIlmImf-2_2-23~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23-debuginfo", rpm: "libIlmImf-2_2-23-debuginfo~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23", rpm: "libIlmImfUtil-2_2-23~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23-debuginfo", rpm: "libIlmImfUtil-2_2-23-debuginfo~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr", rpm: "openexr~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debuginfo", rpm: "openexr-debuginfo~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debugsource", rpm: "openexr-debugsource~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-devel", rpm: "openexr-devel~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-doc", rpm: "openexr-doc~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23-32bit", rpm: "libIlmImf-2_2-23-32bit~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-2_2-23-32bit-debuginfo", rpm: "libIlmImf-2_2-23-32bit-debuginfo~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23-32bit", rpm: "libIlmImfUtil-2_2-23-32bit~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImfUtil-2_2-23-32bit-debuginfo", rpm: "libIlmImfUtil-2_2-23-32bit-debuginfo~2.2.1~lp152.7.11.1", rls: "openSUSELeap15.2" ) )){
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

