if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853789" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-25900" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-02 19:56:00 +0000 (Tue, 02 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-05-01 03:02:18 +0000 (Sat, 01 May 2021)" );
	script_name( "openSUSE: Security Advisory for librsvg (openSUSE-SU-2021:0634-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0634-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HJTKYUPH7JWPY376WTC427MFFFZQ7U7L" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'librsvg'
  package(s) announced via the openSUSE-SU-2021:0634-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for librsvg fixes the following issues:

  - librsvg was updated to 2.46.5:

  * Update dependent crates that had security vulnerabilities: smallvec to
         0.6.14 - RUSTSEC-2018-0003 - CVE-2021-25900 (bsc#1183403)

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'librsvg' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-loader-rsvg", rpm: "gdk-pixbuf-loader-rsvg~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-loader-rsvg-debuginfo", rpm: "gdk-pixbuf-loader-rsvg-debuginfo~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librsvg-2-2", rpm: "librsvg-2-2~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librsvg-2-2-debuginfo", rpm: "librsvg-2-2-debuginfo~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librsvg-debugsource", rpm: "librsvg-debugsource~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librsvg-devel", rpm: "librsvg-devel~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsvg-convert", rpm: "rsvg-convert~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsvg-convert-debuginfo", rpm: "rsvg-convert-debuginfo~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Rsvg-2_0", rpm: "typelib-1_0-Rsvg-2_0~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librsvg-lang", rpm: "librsvg-lang~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsvg-thumbnailer", rpm: "rsvg-thumbnailer~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-loader-rsvg-32bit", rpm: "gdk-pixbuf-loader-rsvg-32bit~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-loader-rsvg-32bit-debuginfo", rpm: "gdk-pixbuf-loader-rsvg-32bit-debuginfo~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librsvg-2-2-32bit", rpm: "librsvg-2-2-32bit~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librsvg-2-2-32bit-debuginfo", rpm: "librsvg-2-2-32bit-debuginfo~2.46.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

