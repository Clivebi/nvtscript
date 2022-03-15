if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874419" );
	script_version( "2021-06-08T11:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-08 11:00:18 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-06 05:45:23 +0200 (Sun, 06 May 2018)" );
	script_cve_id( "CVE-2017-17528" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-29 15:37:00 +0000 (Fri, 29 Dec 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for scummvm-tools FEDORA-2018-3622f44a12" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'scummvm-tools'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "scummvm-tools on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-3622f44a12" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FESRFMTYBCRSK2CYB36QEOH2EJEBANMG" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC26" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC26"){
	if(( res = isrpmvuln( pkg: "scummvm-tools", rpm: "scummvm-tools~2.0.0~1.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
