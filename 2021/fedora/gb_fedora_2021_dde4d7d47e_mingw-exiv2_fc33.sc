if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879909" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2021-29463", "CVE-2021-29464" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-10 15:31:00 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2021-08-02 03:18:32 +0000 (Mon, 02 Aug 2021)" );
	script_name( "Fedora: Security Advisory for mingw-exiv2 (FEDORA-2021-dde4d7d47e)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-dde4d7d47e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/K3HKXR6JOVKMBE4HY4FDXNVZGNCQG6T3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-exiv2'
  package(s) announced via the FEDORA-2021-dde4d7d47e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MinGW Windows exiv2 library." );
	script_tag( name: "affected", value: "'mingw-exiv2' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-exiv2", rpm: "mingw-exiv2~0.27.4~2.fc33", rls: "FC33" ) )){
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

