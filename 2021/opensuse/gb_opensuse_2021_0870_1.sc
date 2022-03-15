if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853859" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2015-9542" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-14 14:28:00 +0000 (Fri, 14 Aug 2020)" );
	script_tag( name: "creation_date", value: "2021-06-15 03:01:43 +0000 (Tue, 15 Jun 2021)" );
	script_name( "openSUSE: Security Advisory for pam_radius (openSUSE-SU-2021:0870-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0870-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3KXPRDBUQG5DRAA3TWBMKHHZP4CR2QEX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pam_radius'
  package(s) announced via the openSUSE-SU-2021:0870-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for pam_radius fixes the following issues:

  - CVE-2015-9542: pam_radius: buffer overflow in password field
       (bsc#1163933)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'pam_radius' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "pam_radius", rpm: "pam_radius~1.4.0~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_radius-debuginfo", rpm: "pam_radius-debuginfo~1.4.0~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_radius-debugsource", rpm: "pam_radius-debugsource~1.4.0~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_radius-32bit", rpm: "pam_radius-32bit~1.4.0~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_radius-32bit-debuginfo", rpm: "pam_radius-32bit-debuginfo~1.4.0~lp152.4.3.1", rls: "openSUSELeap15.2" ) )){
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

