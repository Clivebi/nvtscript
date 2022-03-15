if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878851" );
	script_version( "2021-08-20T14:00:58+0000" );
	script_cve_id( "CVE-2020-35653", "CVE-2020-35654", "CVE-2020-35655" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:00:58 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-22 15:48:00 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-01-25 04:01:28 +0000 (Mon, 25 Jan 2021)" );
	script_name( "Fedora: Security Advisory for python-pillow (FEDORA-2021-880aa7bd27)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2021-880aa7bd27" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BF553AMNNNBW7SH4IM4MNE4M6GNZQ7YD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-pillow'
  package(s) announced via the FEDORA-2021-880aa7bd27 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python image processing library, fork of the Python Imaging Library (PIL)

This library provides extensive file format support, an efficient
internal representation, and powerful image processing capabilities.

There are four subpackages: tk (tk interface), qt (PIL image wrapper for Qt),
devel (development) and doc (documentation)." );
	script_tag( name: "affected", value: "'python-pillow' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "python-pillow", rpm: "python-pillow~7.0.0~5.fc32", rls: "FC32" ) )){
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

