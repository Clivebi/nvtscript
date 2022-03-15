if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883372" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2021-31535" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 13:46:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-08-31 01:00:52 +0000 (Tue, 31 Aug 2021)" );
	script_name( "CentOS: Security Advisory for libX11 (CESA-2021:3296)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:3296" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-August/048354.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libX11'
  package(s) announced via the CESA-2021:3296 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The libX11 packages contain the core X11 protocol client library.

Security Fix(es):

  * libX11: missing request length checks (CVE-2021-31535)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'libX11' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "libX11", rpm: "libX11~1.6.7~4.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-common", rpm: "libX11-common~1.6.7~4.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-devel", rpm: "libX11-devel~1.6.7~4.el7_9", rls: "CentOS7" ) )){
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

