if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883336" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2021-20277" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 19:45:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-11 03:00:38 +0000 (Sun, 11 Apr 2021)" );
	script_name( "CentOS: Security Advisory for ldb-tools (CESA-2021:1072)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:1072" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-April/048299.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ldb-tools'
  package(s) announced via the CESA-2021:1072 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The libldb packages provide an extensible library that implements an
LDAP-like API to access remote LDAP servers, or use local TDB databases.

Security Fix(es):

  * samba: Out of bounds read in AD DC LDAP server (CVE-2021-20277)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'ldb-tools' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "ldb-tools", rpm: "ldb-tools~1.5.4~2.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb", rpm: "libldb~1.5.4~2.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb-devel", rpm: "libldb-devel~1.5.4~2.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pyldb", rpm: "pyldb~1.5.4~2.el7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pyldb-devel", rpm: "pyldb-devel~1.5.4~2.el7", rls: "CentOS7" ) )){
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

