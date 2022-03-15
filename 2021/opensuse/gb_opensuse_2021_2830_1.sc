if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854105" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2021-3711", "CVE-2021-3712" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-31 16:37:00 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-25 03:01:50 +0000 (Wed, 25 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for openssl-1_1 (openSUSE-SU-2021:2830-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2830-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YOUNRN5SCBRRVEIYDG3G3PFLGVRXKDPG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl-1_1'
  package(s) announced via the openSUSE-SU-2021:2830-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssl-1_1 fixes the following security issues:

  - CVE-2021-3711: A bug in the implementation of the SM2 decryption code
       could lead to buffer overflows. [bsc#1189520]

  - CVE-2021-3712: a bug in the code for printing certificate details could
       lead to a buffer overrun that a malicious actor could exploit to crash
       the application, causing a denial-of-service attack. [bsc#1189521]" );
	script_tag( name: "affected", value: "'openssl-1_1' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_1-devel", rpm: "libopenssl-1_1-devel~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1", rpm: "libopenssl1_1~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-debuginfo", rpm: "libopenssl1_1-debuginfo~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-hmac", rpm: "libopenssl1_1-hmac~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1", rpm: "openssl-1_1~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-debuginfo", rpm: "openssl-1_1-debuginfo~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-debugsource", rpm: "openssl-1_1-debugsource~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-doc", rpm: "openssl-1_1-doc~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_1-devel-32bit", rpm: "libopenssl-1_1-devel-32bit~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-32bit", rpm: "libopenssl1_1-32bit~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-32bit-debuginfo", rpm: "libopenssl1_1-32bit-debuginfo~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-hmac-32bit", rpm: "libopenssl1_1-hmac-32bit~1.1.1d~11.27.1", rls: "openSUSELeap15.3" ) )){
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
