if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883368" );
	script_version( "2021-08-24T09:58:36+0000" );
	script_cve_id( "CVE-2021-31291" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 09:58:36 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-19 03:00:39 +0000 (Thu, 19 Aug 2021)" );
	script_name( "CentOS: Security Advisory for exiv2 (CESA-2021:3158)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:3158" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-August/048349.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exiv2'
  package(s) announced via the CESA-2021:3158 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Exiv2 is a C++ library to access image metadata, supporting read and write
access to the Exif, IPTC and XMP metadata, Exif MakerNote support, extract
and delete methods for Exif thumbnails, classes to access Ifd, and support
for various image formats.

Security Fix(es):

  * exiv2: Heap-based buffer overflow vulnerability in jp2image.cpp
(CVE-2021-31291)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'exiv2' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "exiv2", rpm: "exiv2~0.27.0~4.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exiv2-devel", rpm: "exiv2-devel~0.27.0~4.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exiv2-doc", rpm: "exiv2-doc~0.27.0~4.el7_8", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exiv2-libs", rpm: "exiv2-libs~0.27.0~4.el7_8", rls: "CentOS7" ) )){
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

