if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877400" );
	script_version( "2021-07-22T02:00:50+0000" );
	script_cve_id( "CVE-2020-5313", "CVE-2020-5312", "CVE-2020-5311", "CVE-2020-5310", "CVE-2019-16865" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-22 02:00:50 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-31 04:03:38 +0000 (Fri, 31 Jan 2020)" );
	script_name( "Fedora: Security Advisory for python-pillow (FEDORA-2020-df444e464e)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-df444e464e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2MMU3WT2X64GS5WHDPKKC2WZA7UIIQ3A" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-pillow'
  package(s) announced via the FEDORA-2020-df444e464e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python image processing library, fork of the Python Imaging Library (PIL)

This library provides extensive file format support, an efficient
internal representation, and powerful image processing capabilities.

There are four subpackages: tk (tk interface), qt (PIL image wrapper for Qt),
devel (development) and doc (documentation)." );
	script_tag( name: "affected", value: "'python-pillow' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "python-pillow", rpm: "python-pillow~6.2.2~1.fc31", rls: "FC31" ) )){
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

