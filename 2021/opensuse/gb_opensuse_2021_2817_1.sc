if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854101" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-26137" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 21:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-08-24 03:01:45 +0000 (Tue, 24 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for aws-cli, (openSUSE-SU-2021:2817-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2817-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TOZI5ZFPFR2BACIE74HUJWDXC2ZWXNGD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aws-cli, '
  package(s) announced via the openSUSE-SU-2021:2817-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This patch updates the Python AWS SDK stack in SLE 15:

     General:

     # aws-cli

  - Version updated to upstream release v1.19.9 For a detailed list of all
       changes, please refer to the changelog file of this package.

     # python-boto3

  - Version updated to upstream release 1.17.9 For a detailed list of all
       changes, please refer to the changelog file of this package.

     # python-botocore

  - Version updated to upstream release 1.20.9 For a detailed list of all
       changes, please refer to the changelog file of this package.

     # python-urllib3

  - Version updated to upstream release 1.25.10 For a detailed list of all
       changes, please refer to the changelog file of this package.

     # python-service_identity

  - Added this new package to resolve runtime dependencies for other
       packages. Version: 18.1.0

     # python-trustme

  - Added this new package to resolve runtime dependencies for other
       packages. Version: 0.6.0

     Security fixes:

     # python-urllib3:

  - CVE-2020-26137: urllib3 before 1.25.9 allows CRLF injection if the
       attacker controls the HTTP request method, as demonstrated by inserting
       CR and LF control characters in the first argument of putrequest()
       (bsc#1177120)" );
	script_tag( name: "affected", value: "'aws-cli, ' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-cffi-debuginfo", rpm: "python-cffi-debuginfo~1.13.2~3.2.5", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cffi-debugsource", rpm: "python-cffi-debugsource~1.13.2~3.2.5", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cryptography-debuginfo", rpm: "python-cryptography-debuginfo~2.8~10.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cryptography-debugsource", rpm: "python-cryptography-debugsource~2.8~10.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-cffi", rpm: "python2-cffi~1.13.2~3.2.5", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-cffi-debuginfo", rpm: "python2-cffi-debuginfo~1.13.2~3.2.5", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-cryptography", rpm: "python2-cryptography~2.8~10.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-cryptography-debuginfo", rpm: "python2-cryptography-debuginfo~2.8~10.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-cffi", rpm: "python3-cffi~1.13.2~3.2.5", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-cffi-debuginfo", rpm: "python3-cffi-debuginfo~1.13.2~3.2.5", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-cryptography", rpm: "python3-cryptography~2.8~10.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-cryptography-debuginfo", rpm: "python3-cryptography-debuginfo~2.8~10.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aws-cli", rpm: "aws-cli~1.19.9~26.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-asn1crypto", rpm: "python2-asn1crypto~0.24.0~3.2.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-boto3", rpm: "python2-boto3~1.17.9~19.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-botocore", rpm: "python2-botocore~1.20.9~33.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-pyasn1", rpm: "python2-pyasn1~0.4.2~3.2.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-pycparser", rpm: "python2-pycparser~2.17~3.2.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-urllib3", rpm: "python2-urllib3~1.25.10~9.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-asn1crypto", rpm: "python3-asn1crypto~0.24.0~3.2.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-boto3", rpm: "python3-boto3~1.17.9~19.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-botocore", rpm: "python3-botocore~1.20.9~33.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-pyasn1", rpm: "python3-pyasn1~0.4.2~3.2.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-pycparser", rpm: "python3-pycparser~2.17~3.2.1", rls: "openSUSELeap15.3" ) )){
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

