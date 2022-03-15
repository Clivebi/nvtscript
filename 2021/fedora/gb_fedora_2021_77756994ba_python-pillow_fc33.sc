if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879674" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2021-28675", "CVE-2021-28678", "CVE-2021-25287", "CVE-2021-25288", "CVE-2021-28676", "CVE-2021-28677" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 07:15:00 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-03 06:24:08 +0000 (Thu, 03 Jun 2021)" );
	script_name( "Fedora: Security Advisory for python-pillow (FEDORA-2021-77756994ba)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-77756994ba" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CTEBUCQIRI7KHPUU4IC3X56S2KIHMEVY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-pillow'
  package(s) announced via the FEDORA-2021-77756994ba advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python image processing library, fork of the Python Imaging Library (PIL)

This library provides extensive file format support, an efficient
internal representation, and powerful image processing capabilities.

There are four subpackages: tk (tk interface), qt (PIL image wrapper for Qt),
devel (development) and doc (documentation)." );
	script_tag( name: "affected", value: "'python-pillow' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "python-pillow", rpm: "python-pillow~7.2.0~6.fc33", rls: "FC33" ) )){
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

