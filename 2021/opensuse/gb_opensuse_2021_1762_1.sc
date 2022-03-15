if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853954" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-22898" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:05:22 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for curl (openSUSE-SU-2021:1762-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1762-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OBJDOC5P7XCTDSENHRNLNXYRSHFI4CYU" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the openSUSE-SU-2021:1762-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for curl fixes the following issues:

  - CVE-2021-22898: Fixed curl TELNET stack contents disclosure
       (bsc#1186114).

  - Allow partial chain verification [jsc#SLE-17956]

  * Have intermediate certificates in the trust store be treated as
         trust-anchors, in the same way as self-signed root CA certificates
         are. This allows users to verify servers using the intermediate cert
         only, instead of needing the whole chain.

  * Set FLAG_TRUSTED_FIRST unconditionally.

  * Do not check partial chains with CRL check." );
	script_tag( name: "affected", value: "'curl' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "curl", rpm: "curl~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debuginfo", rpm: "curl-debuginfo~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debugsource", rpm: "curl-debugsource~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-mini", rpm: "curl-mini~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-mini-debuginfo", rpm: "curl-mini-debuginfo~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-mini-debugsource", rpm: "curl-mini-debugsource~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-devel", rpm: "libcurl-devel~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-mini-devel", rpm: "libcurl-mini-devel~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4", rpm: "libcurl4~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-debuginfo", rpm: "libcurl4-debuginfo~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-mini", rpm: "libcurl4-mini~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-mini-debuginfo", rpm: "libcurl4-mini-debuginfo~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-devel-32bit", rpm: "libcurl-devel-32bit~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-32bit", rpm: "libcurl4-32bit~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-32bit-debuginfo", rpm: "libcurl4-32bit-debuginfo~7.66.0~4.17.1", rls: "openSUSELeap15.3" ) )){
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

