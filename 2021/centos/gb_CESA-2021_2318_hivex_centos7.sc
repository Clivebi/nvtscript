if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883353" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2021-3504" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 18:35:00 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-15 03:01:03 +0000 (Tue, 15 Jun 2021)" );
	script_name( "CentOS: Security Advisory for hivex (CESA-2021:2318)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:2318" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-June/048330.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'hivex'
  package(s) announced via the CESA-2021:2318 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Hivex is a library that can read and write Hive files, undocumented binary
files that Windows uses to store the Windows Registry on disk.

Security Fix(es):

  * hivex: Buffer overflow when provided invalid node key length
(CVE-2021-3504)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'hivex' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "hivex", rpm: "hivex~1.3.10~6.11.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "hivex-devel", rpm: "hivex-devel~1.3.10~6.11.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-hivex", rpm: "ocaml-hivex~1.3.10~6.11.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ocaml-hivex-devel", rpm: "ocaml-hivex-devel~1.3.10~6.11.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-hivex", rpm: "perl-hivex~1.3.10~6.11.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-hivex", rpm: "python-hivex~1.3.10~6.11.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-hivex", rpm: "ruby-hivex~1.3.10~6.11.el7_9", rls: "CentOS7" ) )){
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

