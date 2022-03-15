if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.0117.1" );
	script_cve_id( "CVE-2016-0777", "CVE-2016-0778" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:09 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:0117-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:0117-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20160117-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh-openssl1' package(s) announced via the SUSE-SU-2016:0117-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssh-openssl1 fixes the following issues:
- CVE-2016-0777: A malicious or compromised server could cause the OpenSSH
 client to expose part or all of the client's private key through the
 roaming feature (bsc#961642)
- CVE-2016-0778: A malicious or compromised server could could trigger a
 buffer overflow in the OpenSSH client through the roaming feature
 (bsc#961645)
This update disables the undocumented feature supported by the OpenSSH client and a commercial SSH server." );
	script_tag( name: "affected", value: "'openssh-openssl1' package(s) on SUSE Linux Enterprise Server 11." );
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
if(release == "SLES11.0"){
	if(!isnull( res = isrpmvuln( pkg: "openssh-openssl1", rpm: "openssh-openssl1~6.6p1~10.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-openssl1-helpers", rpm: "openssh-openssl1-helpers~6.6p1~10.1", rls: "SLES11.0" ) )){
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

