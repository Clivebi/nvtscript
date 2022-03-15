if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883007" );
	script_version( "2021-08-27T14:01:18+0000" );
	script_cve_id( "CVE-2019-3813" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 14:01:18 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-02-10 04:04:18 +0100 (Sun, 10 Feb 2019)" );
	script_name( "CentOS Update for spice-server CESA-2019:0231 centos7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:0231" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-February/023192.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-server'
  package(s) announced via the CESA-2019:0231 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Simple Protocol for Independent Computing Environments (SPICE) is a
remote display system built for virtual environments which allows the user
to view a computing 'desktop' environment not only on the machine where it
is running, but from anywhere on the Internet and from a wide variety of
machine architectures.

Security Fix(es):

  * spice: Off-by-one error in array access in spice/server/memslot.c
(CVE-2019-3813)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

This issue was discovered by Christophe Fergeau (Red Hat)." );
	script_tag( name: "affected", value: "spice-server on CentOS 7." );
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
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "spice-server", rpm: "spice-server~0.14.0~6.el7_6.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "spice-server-devel", rpm: "spice-server-devel~0.14.0~6.el7_6.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

