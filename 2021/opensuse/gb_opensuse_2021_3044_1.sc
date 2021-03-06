if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854167" );
	script_version( "2021-09-22T05:42:45+0000" );
	script_cve_id( "CVE-2021-3781" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 05:42:45 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-16 01:02:03 +0000 (Thu, 16 Sep 2021)" );
	script_name( "openSUSE: Security Advisory for ghostscript (openSUSE-SU-2021:3044-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:3044-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M64NXCVRRUDYD4U65CYH2ROCOGMSYF3U" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript'
  package(s) announced via the openSUSE-SU-2021:3044-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ghostscript fixes the following issues:

     Security issue fixed:

  - CVE-2021-3781: Fixed a trivial -dSAFER bypass command injection
       (bsc#1190381)

     Also a hardening fix was added:

  - Link as position independent executable (bsc#1184123)" );
	script_tag( name: "affected", value: "'ghostscript' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.52~155.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-debuginfo", rpm: "ghostscript-debuginfo~9.52~155.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-debugsource", rpm: "ghostscript-debugsource~9.52~155.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-devel", rpm: "ghostscript-devel~9.52~155.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11", rpm: "ghostscript-x11~9.52~155.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11-debuginfo", rpm: "ghostscript-x11-debuginfo~9.52~155.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspectre-debugsource", rpm: "libspectre-debugsource~0.2.8~3.12.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspectre-devel", rpm: "libspectre-devel~0.2.8~3.12.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspectre1", rpm: "libspectre1~0.2.8~3.12.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspectre1-debuginfo", rpm: "libspectre1-debuginfo~0.2.8~3.12.1", rls: "openSUSELeap15.3" ) )){
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

