if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851876" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-04 07:03:19 +0200 (Tue, 04 Sep 2018)" );
	script_cve_id( "CVE-2018-12434", "CVE-2018-8970" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-24 16:40:00 +0000 (Tue, 24 Apr 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for libressl (openSUSE-SU-2018:2597-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libressl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libressl to version 2.8.0 fixes the following issues:

  Security issues fixed:

  - CVE-2018-12434: Avoid a timing side-channel leak when generating DSA and
  ECDSA signatures. (boo#1097779)

  - Reject excessively large primes in DH key generation.

  - CVE-2018-8970: Fixed a bug in int_x509_param_set_hosts, calling strlen()
  if name length provided is 0 to match the OpenSSL behaviour.
  (boo#1086778)

  - Fixed an out-of-bounds read and crash in DES-fcrypt (boo#1065363)

  You can find a detailed list of changes in the linked references.
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-953=1" );
	script_tag( name: "affected", value: "libressl on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2597-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00004.html" );
	script_xref( name: "URL", value: "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.0-relnotes" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libcrypto43", rpm: "libcrypto43~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcrypto43-debuginfo", rpm: "libcrypto43-debuginfo~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libressl", rpm: "libressl~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libressl-debuginfo", rpm: "libressl-debuginfo~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libressl-debugsource", rpm: "libressl-debugsource~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libressl-devel", rpm: "libressl-devel~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssl45", rpm: "libssl45~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssl45-debuginfo", rpm: "libssl45-debuginfo~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtls17", rpm: "libtls17~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtls17-debuginfo", rpm: "libtls17-debuginfo~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcrypto43-32bit", rpm: "libcrypto43-32bit~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcrypto43-debuginfo-32bit", rpm: "libcrypto43-debuginfo-32bit~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libressl-devel-32bit", rpm: "libressl-devel-32bit~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssl45-32bit", rpm: "libssl45-32bit~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssl45-debuginfo-32bit", rpm: "libssl45-debuginfo-32bit~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtls17-32bit", rpm: "libtls17-32bit~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtls17-debuginfo-32bit", rpm: "libtls17-debuginfo-32bit~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libressl-devel-doc", rpm: "libressl-devel-doc~2.8.0~11.1", rls: "openSUSELeap42.3" ) )){
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

