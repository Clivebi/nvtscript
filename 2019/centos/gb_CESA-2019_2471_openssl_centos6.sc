if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883097" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_cve_id( "CVE-2019-1559" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-08-17 02:00:49 +0000 (Sat, 17 Aug 2019)" );
	script_name( "CentOS Update for openssl CESA-2019:2471 centos6 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2019:2471" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-August/023403.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the CESA-2019:2471 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL) and
Transport Layer Security (TLS) protocols, as well as a full-strength
general-purpose cryptography library.

Security Fix(es):

  * openssl: 0-byte record padding oracle (CVE-2019-1559)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'openssl' package(s) on CentOS 6." );
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
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1e~58.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~1.0.1e~58.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~1.0.1e~58.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-static", rpm: "openssl-static~1.0.1e~58.el6_10", rls: "CentOS6" ) )){
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

