if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877878" );
	script_version( "2021-07-21T02:01:11+0000" );
	script_cve_id( "CVE-2018-10756" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-14 14:28:00 +0000 (Fri, 14 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-05-29 03:28:57 +0000 (Fri, 29 May 2020)" );
	script_name( "Fedora: Security Advisory for transmission (FEDORA-2020-e67318b4b4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-e67318b4b4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OVAG2HNKNRLWOACFN5F2ANJD2SQ53WI7" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'transmission'
  package(s) announced via the FEDORA-2020-e67318b4b4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Transmission is a free, lightweight BitTorrent client. It features a
simple, intuitive interface on top on an efficient, cross-platform
back-end." );
	script_tag( name: "affected", value: "'transmission' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "transmission", rpm: "transmission~2.94~9.fc32", rls: "FC32" ) )){
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

