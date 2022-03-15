if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883167" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_cve_id( "CVE-2019-5544" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-15 00:15:00 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "creation_date", value: "2020-01-29 04:01:03 +0000 (Wed, 29 Jan 2020)" );
	script_name( "CentOS: Security Advisory for openslp (CESA-2020:0199)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:0199" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-January/035608.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openslp'
  package(s) announced via the CESA-2020:0199 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenSLP is an open source implementation of the Service Location Protocol
(SLP) which is an Internet Engineering Task Force (IETF) standards track
protocol and provides a framework to allow networking applications to
discover the existence, location, and configuration of networked services
in enterprise networks.

Security Fix(es):

  * openslp: Heap-based buffer overflow in ProcessSrvRqst() in slpd_process.c
leading to remote code execution (CVE-2019-5544)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'openslp' package(s) on CentOS 6." );
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
	if(!isnull( res = isrpmvuln( pkg: "openslp", rpm: "openslp~2.0.0~4.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openslp-devel", rpm: "openslp-devel~2.0.0~4.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openslp-server", rpm: "openslp-server~2.0.0~4.el6_10", rls: "CentOS6" ) )){
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

