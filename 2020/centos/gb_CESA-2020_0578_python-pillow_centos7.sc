if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883190" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2019-16865", "CVE-2020-5312" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-02-27 04:00:35 +0000 (Thu, 27 Feb 2020)" );
	script_name( "CentOS: Security Advisory for python-pillow (CESA-2020:0578)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:0578" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-February/035646.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-pillow'
  package(s) announced via the CESA-2020:0578 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The python-pillow packages contain a Python image processing library that
provides extensive file format support, an efficient internal
representation, and powerful image-processing capabilities.

Security Fix(es):

  * python-pillow: improperly restricted operations on memory buffer in
libImaging/PcxDecode.c (CVE-2020-5312)

  * python-pillow: reading specially crafted image files leads to allocation
of large amounts of memory and denial of service (CVE-2019-16865)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'python-pillow' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-pillow", rpm: "python-pillow~2.0.0~20.gitd1c6db8.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-pillow-devel", rpm: "python-pillow-devel~2.0.0~20.gitd1c6db8.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-pillow-doc", rpm: "python-pillow-doc~2.0.0~20.gitd1c6db8.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-pillow-qt", rpm: "python-pillow-qt~2.0.0~20.gitd1c6db8.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-pillow-sane", rpm: "python-pillow-sane~2.0.0~20.gitd1c6db8.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-pillow-tk", rpm: "python-pillow-tk~2.0.0~20.gitd1c6db8.el7_7", rls: "CentOS7" ) )){
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

