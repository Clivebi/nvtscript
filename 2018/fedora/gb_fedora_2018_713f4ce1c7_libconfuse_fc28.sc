if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875286" );
	script_version( "2021-06-10T11:00:22+0000" );
	script_cve_id( "CVE-2018-14447" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-10 11:00:22 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-14 13:15:00 +0000 (Fri, 14 Sep 2018)" );
	script_tag( name: "creation_date", value: "2018-11-28 08:36:26 +0100 (Wed, 28 Nov 2018)" );
	script_name( "Fedora Update for libconfuse FEDORA-2018-713f4ce1c7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2018-713f4ce1c7" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UQNPFOHU42XZSP322DZUSQCPRCWDEXSO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libconfuse'
  package(s) announced via the FEDORA-2018-713f4ce1c7 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "libconfuse on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "libconfuse", rpm: "libconfuse~3.2.2~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

