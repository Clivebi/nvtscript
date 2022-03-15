if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883307" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2016-5766" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)" );
	script_tag( name: "creation_date", value: "2020-12-18 04:01:14 +0000 (Fri, 18 Dec 2020)" );
	script_name( "CentOS: Security Advisory for gd (CESA-2020:5443)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:5443" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-December/048237.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gd'
  package(s) announced via the CESA-2020:5443 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GD is an open source code library for the dynamic creation of images by
programmers. GD creates PNG, JPEG, GIF, WebP, XPM, BMP images, among other
formats.

Security Fix(es):

  * gd: Integer overflow in _gd2GetHeader() resulting in heap overflow
(CVE-2016-5766)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'gd' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "gd", rpm: "gd~2.0.35~27.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gd-devel", rpm: "gd-devel~2.0.35~27.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gd-progs", rpm: "gd-progs~2.0.35~27.el7_9", rls: "CentOS7" ) )){
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

