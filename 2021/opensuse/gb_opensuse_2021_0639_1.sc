if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853788" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2020-14342", "CVE-2021-20208" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-29 14:56:00 +0000 (Thu, 29 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-05-01 03:02:15 +0000 (Sat, 01 May 2021)" );
	script_name( "openSUSE: Security Advisory for cifs-utils (openSUSE-SU-2021:0639-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0639-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/65NUX6IGI72XJIWLCF5QOKIKAWWJUMEY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cifs-utils'
  package(s) announced via the openSUSE-SU-2021:0639-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cifs-utils fixes the following security issues:

  - CVE-2021-20208: Fixed a potential kerberos auth leak escaping from
       container. (bsc#1183239)

  - CVE-2020-14342: Fixed a shell command injection vulnerability in
       mount.cifs. (bsc#1174477)

     This update for cifs-utils fixes the following issues:

  - Solve invalid directory mounting. When attempting to change the current
       working directory into non-existing directories, mount.cifs crashes.
       (bsc#1152930)

  - Fixed a bug where it was no longer possible to mount CIFS filesystem
       after the last maintenance update. (bsc#1184815)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'cifs-utils' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "cifs-utils", rpm: "cifs-utils~6.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cifs-utils-debuginfo", rpm: "cifs-utils-debuginfo~6.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cifs-utils-debugsource", rpm: "cifs-utils-debugsource~6.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cifs-utils-devel", rpm: "cifs-utils-devel~6.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_cifscreds", rpm: "pam_cifscreds~6.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pam_cifscreds-debuginfo", rpm: "pam_cifscreds-debuginfo~6.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

