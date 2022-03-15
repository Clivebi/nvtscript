if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853793" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-23961", "CVE-2021-23994", "CVE-2021-23995", "CVE-2021-23998", "CVE-2021-23999", "CVE-2021-24002", "CVE-2021-29945", "CVE-2021-29946", "CVE-2021-29948" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-02 16:55:00 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-02 03:01:06 +0000 (Sun, 02 May 2021)" );
	script_name( "openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2021:0644-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0644-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FZF7QZJOUTVUSU5SPVGG757XUPT3OVD3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2021:0644-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaThunderbird fixes the following issues:

  - Firefox was updated to 78.10.0 ESR (bsc#1184960)

  * CVE-2021-23994: Out of bound write due to lazy initialization

  * CVE-2021-23995: Use-after-free in Responsive Design Mode

  * CVE-2021-23998: Secure Lock icon could have been spoofed

  * CVE-2021-23961: More internal network hosts could have been probed by
         a malicious webpage

  * CVE-2021-23999: Blob URLs may have been granted additional privileges

  * CVE-2021-24002: Arbitrary FTP command execution on FTP servers using
         an encoded URL

  * CVE-2021-29945: Incorrect size computation in WebAssembly JIT could
         lead to null-reads

  * CVE-2021-29946: Port blocking could be bypassed

  * CVE-2021-29948: Race condition when reading from disk while verifying
         signatures

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'MozillaThunderbird' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird", rpm: "MozillaThunderbird~78.10.0~lp152.2.41.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debuginfo", rpm: "MozillaThunderbird-debuginfo~78.10.0~lp152.2.41.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debugsource", rpm: "MozillaThunderbird-debugsource~78.10.0~lp152.2.41.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-common", rpm: "MozillaThunderbird-translations-common~78.10.0~lp152.2.41.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-other", rpm: "MozillaThunderbird-translations-other~78.10.0~lp152.2.41.1", rls: "openSUSELeap15.2" ) )){
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

