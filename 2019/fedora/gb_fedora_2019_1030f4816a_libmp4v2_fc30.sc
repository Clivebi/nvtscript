if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877029" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2018-14446", "CVE-2018-14403", "CVE-2018-14379", "CVE-2018-14326", "CVE-2018-14325", "CVE-2018-14054" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-17 19:15:00 +0000 (Sun, 17 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-21 03:39:41 +0000 (Thu, 21 Nov 2019)" );
	script_name( "Fedora Update for libmp4v2 FEDORA-2019-1030f4816a" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-1030f4816a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FRSO2IMK6P7MOIZWGWKONPIEHKBA7WL3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmp4v2'
  package(s) announced via the FEDORA-2019-1030f4816a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The libmp4v2 library provides an abstraction layer for working with files
using the mp4 container format. This library is developed by mpeg4ip project
and is an exact copy of the library distributed in the mpeg4ip package." );
	script_tag( name: "affected", value: "'libmp4v2' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "libmp4v2", rpm: "libmp4v2~2.1.0~0.19.trunkREV507.fc30", rls: "FC30" ) )){
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

