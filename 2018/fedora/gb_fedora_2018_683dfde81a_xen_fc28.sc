if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875010" );
	script_version( "2021-06-14T11:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 11:00:34 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-30 07:24:42 +0200 (Thu, 30 Aug 2018)" );
	script_cve_id( "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-12891", "CVE-2018-12893", "CVE-2018-12892", "CVE-2018-3665", "CVE-2018-3639", "CVE-2018-8897", "CVE-2018-10982", "CVE-2018-10981", "CVE-2018-10472", "CVE-2018-10471", "CVE-2018-15469", "CVE-2018-15468", "CVE-2018-15470" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for xen FEDORA-2018-683dfde81a" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "xen on Fedora 28" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-683dfde81a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GOBWAAGQGXLQJKTEI5JYA4HQNK4EI4XY" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
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
	if(( res = isrpmvuln( pkg: "xen", rpm: "xen~4.10.1~6.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

