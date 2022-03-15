if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852023" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_cve_id( "CVE-2018-0732" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-08 12:15:00 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:35:10 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for openssl-1_1 (openSUSE-SU-2018:2117-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2117-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-07/msg00034.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl-1_1'
  package(s) announced via the openSUSE-SU-2018:2117-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssl-1_1 fixes the following issues:

  - CVE-2018-0732: During key agreement in a TLS handshake using a DH(E)
  based ciphersuite a malicious server could have sent a very large prime
  value to the client. This caused the client to spend an unreasonably
  long period of time generating a key for this prime resulting in a hang
  until the client has finished. This could be exploited in a Denial Of
  Service attack (bsc#1097158).

  - Blinding enhancements for ECDSA and DSA (bsc#1097624, bsc#1098592)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-777=1" );
	script_tag( name: "affected", value: "openssl-1_1 on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_1-devel", rpm: "libopenssl-1_1-devel~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1", rpm: "libopenssl1_1~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-debuginfo", rpm: "libopenssl1_1-debuginfo~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-hmac", rpm: "libopenssl1_1-hmac~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1", rpm: "openssl-1_1~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-debuginfo", rpm: "openssl-1_1-debuginfo~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-debugsource", rpm: "openssl-1_1-debugsource~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_1-devel-32bit", rpm: "libopenssl-1_1-devel-32bit~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-32bit", rpm: "libopenssl1_1-32bit~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-32bit-debuginfo", rpm: "libopenssl1_1-32bit-debuginfo~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_1-hmac-32bit", rpm: "libopenssl1_1-hmac-32bit~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_1-doc", rpm: "openssl-1_1-doc~1.1.0h~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
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

