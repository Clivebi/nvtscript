if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879416" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2021-3426" );
	script_tag( name: "cvss_base", value: "2.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 10:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-24 03:08:10 +0000 (Sat, 24 Apr 2021)" );
	script_name( "Fedora: Security Advisory for python3-docs (FEDORA-2021-067c9deff1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-067c9deff1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QNGAFMPIYIVJ47FCF2NK2PIX22HUG35B" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3-docs'
  package(s) announced via the FEDORA-2021-067c9deff1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The python3-docs package contains documentation on the Python 3
programming language and interpreter." );
	script_tag( name: "affected", value: "'python3-docs' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "python3-docs", rpm: "python3-docs~3.9.4~1.fc33", rls: "FC33" ) )){
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

