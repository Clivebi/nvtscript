if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879473" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_cve_id( "CVE-2020-25693" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-05 13:06:00 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-26 03:06:16 +0000 (Mon, 26 Apr 2021)" );
	script_name( "Fedora: Security Advisory for CImg (FEDORA-2021-2aaba884af)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-2aaba884af" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ERBZALTF7LXN2LZLPGAUSVMV53GHHTUC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'CImg'
  package(s) announced via the FEDORA-2021-2aaba884af advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The CImg Library is an open-source C++ toolkit for image processing.
It consists in a single header file &#39, CImg.h&#39, providing a minimal set of C++
classes and methods that can be used in your own sources, to load/save,
process and display images. Very portable, efficient and easy to use,
it&#39, s a pleasant library for developping image processing algorithms in C++." );
	script_tag( name: "affected", value: "'CImg' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "CImg", rpm: "CImg~2.9.7~1.fc34", rls: "FC34" ) )){
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

